#include "app/mainwindow.h"

#include <QApplication>
#include <QHeaderView>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPainter>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QToolBar>
#include <QTreeWidget>
#include <QVBoxLayout>

#include "app/extensiondetail.h"
#include "app/settingsdialog.h"
#include "core/rules.h"

namespace extwatch {

namespace {

QIcon dotIcon(const QColor& color, bool hollow) {
    QPixmap pm(16, 16);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    if (hollow) {
        p.setPen(QPen(color, 1.5));
        p.setBrush(Qt::NoBrush);
    } else {
        p.setPen(Qt::NoPen);
        p.setBrush(color);
    }
    p.drawEllipse(QRectF(4, 4, 8, 8));
    return QIcon(pm);
}

QColor colorFor(const QString& severity) {
    if (severity == QStringLiteral("high")) return QColor(0xe5, 0x48, 0x48);
    if (severity == QStringLiteral("medium")) return QColor(0xe0, 0x8e, 0x1a);
    if (severity == QStringLiteral("low")) return QColor(0x3b, 0x82, 0xf6);
    if (severity == QStringLiteral("info")) return QColor(0x8b, 0x93, 0xa7);
    return QColor(0x4c, 0xaf, 0x50);
}

}  // namespace

MainWindow::MainWindow(QString dataDir, QWidget* parent)
    : QMainWindow(parent), m_dataDir(std::move(dataDir)) {
    m_db.open(databasePath(m_dataDir));
    setWindowTitle(QStringLiteral("ExtWatch"));
    setWindowIcon(QIcon(QStringLiteral(":/app/icons/app.svg")));
    resize(1280, 800);

    QToolBar* bar = addToolBar(QStringLiteral("Main"));
    bar->setMovable(false);
    bar->setToolButtonStyle(Qt::ToolButtonTextOnly);
    m_search = new QLineEdit(this);
    m_search->setPlaceholderText(QStringLiteral("Filter extensions…"));
    m_search->setClearButtonEnabled(true);
    m_search->setMaximumWidth(280);
    connect(m_search, &QLineEdit::textChanged, this, &MainWindow::applyFilter);
    bar->addWidget(m_search);
    QAction* rescan = bar->addAction(QStringLiteral("Rescan now"));
    connect(rescan, &QAction::triggered, this, &MainWindow::rescanRequested);
    auto* spacer = new QWidget(this);
    spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    bar->addWidget(spacer);
    QAction* settings = bar->addAction(QStringLiteral("Settings…"));
    connect(settings, &QAction::triggered, this, &MainWindow::openSettings);

    auto* splitter = new QSplitter(Qt::Horizontal, this);
    m_tree = new QTreeWidget(splitter);
    m_tree->setHeaderLabels({QStringLiteral("Extension"), QStringLiteral("Version")});
    m_tree->setRootIsDecorated(false);
    m_tree->setUniformRowHeights(true);
    m_tree->setIndentation(12);
    m_tree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_tree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_tree->setMinimumWidth(280);
    connect(m_tree, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem*, QTreeWidgetItem*) { onSelectionChanged(); });

    m_stack = new QStackedWidget(splitter);
    m_welcome = new QLabel(m_stack);
    m_welcome->setAlignment(Qt::AlignCenter);
    m_welcome->setWordWrap(true);
    m_welcome->setTextFormat(Qt::RichText);
    m_welcome->setMargin(40);
    m_stack->addWidget(m_welcome);
    m_detail = new ExtensionDetailView(m_dataDir, m_stack);
    connect(m_detail, &ExtensionDetailView::inventoryChanged, this, &MainWindow::rescanRequested);
    connect(m_detail, &ExtensionDetailView::eventAcknowledged, this, [this]() {
        reloadTree();
        emit eventAcknowledged();
    });
    connect(m_detail, &ExtensionDetailView::toggleEnabledRequested, this, &MainWindow::toggleEnabledRequested);
    connect(m_detail, &ExtensionDetailView::companionSetupRequested, this, &MainWindow::companionSetupRequested);
    m_stack->addWidget(m_detail);
    splitter->addWidget(m_tree);
    splitter->addWidget(m_stack);
    splitter->setStretchFactor(0, 0);
    splitter->setStretchFactor(1, 1);
    splitter->setSizes({320, 960});
    setCentralWidget(splitter);

    m_status = new QLabel(QStringLiteral("Waiting for the first scan…"), this);
    statusBar()->addWidget(m_status, 1);
    reloadTree();
}

void MainWindow::showScanResult(const ScanResult& result) {
    m_lastScan = result.scannedAt;
    m_extensionCount = result.extensionCount();
    m_profileCount = result.profileCount();
    reloadTree();
    if (m_stack->currentWidget() == m_detail) {
        m_detail->refresh();
    }
}

void MainWindow::reloadTree() {
    const qint64 selected = m_detail->extensionRowId();
    m_tree->blockSignals(true);
    m_tree->clear();
    m_unacknowledged = 0;
    int extensions = 0;
    int profiles = 0;
    QStringList recent;
    for (const BrowserRow& b : m_db.browsers()) {
        for (const ProfileRow& p : m_db.profilesForBrowser(b.id)) {
            const QList<ExtensionRow> exts = m_db.extensionsForProfile(p.id, /*presentOnly=*/true);
            if (exts.isEmpty()) {
                continue;
            }
            profiles++;
            auto* group = new QTreeWidgetItem(m_tree);
            group->setText(0, QStringLiteral("%1 · %2").arg(b.displayName, p.displayName));
            group->setText(1, QString::number(exts.size()));
            QFont bold = group->font(0);
            bold.setWeight(QFont::DemiBold);
            group->setFont(0, bold);
            group->setFlags(group->flags() & ~Qt::ItemIsSelectable);
            group->setExpanded(true);
            for (const ExtensionRow& e : exts) {
                const QList<EventRow> events = m_db.eventsForExtension(e.id);
                extensions++;
                auto* item = new QTreeWidgetItem(group);
                item->setData(0, Qt::UserRole, e.id);
                item->setText(0, e.name.isEmpty() ? e.extId : e.name);
                QString version;
                if (e.currentVersionId) {
                    if (const auto v = m_db.versionById(*e.currentVersionId)) version = v->version;
                }
                item->setText(1, version);
                QString severity;
                QString tip = e.extId;
                for (auto it = events.crbegin(); it != events.crend(); ++it) {
                    if (it->kind != QStringLiteral("baseline") && !it->acknowledged) {
                        if (severity.isEmpty()) {
                            severity = it->maxSeverity.isEmpty() ? QStringLiteral("info") : it->maxSeverity;
                            if (!it->findingsJson.isEmpty()) {
                                tip += u'\n' + findingsSummary(findingsFromJson(QJsonDocument::fromJson(it->findingsJson.toUtf8()).array()), 4);
                            }
                        }
                        m_unacknowledged++;
                        if (recent.size() < 5) {
                            recent.append(e.name);
                        }
                        break;
                    }
                }
                item->setIcon(0, dotIcon(severity.isEmpty() ? QColor(0x4c, 0xaf, 0x50) : colorFor(severity), !e.enabled));
                if (!e.enabled) {
                    item->setForeground(0, palette().color(QPalette::Disabled, QPalette::Text));
                    item->setText(0, item->text(0) + QStringLiteral("  (disabled)"));
                }
                if (!severity.isEmpty()) {
                    QFont f = item->font(0);
                    f.setBold(true);
                    item->setFont(0, f);
                }
                item->setToolTip(0, tip);
            }
            if (group->childCount() == 0) {
                // Every extension of this profile was removed (or the profile itself is gone).
                delete group;
                profiles--;
            }
        }
    }
    m_tree->blockSignals(false);
    if (selected >= 0) {
        selectExtensionItem(selected);
    }
    applyFilter(m_search->text());

    QString welcome = QStringLiteral("<div style='font-size:26px;font-weight:600;margin-bottom:8px'>ExtWatch</div>");
    if (extensions == 0) {
        welcome += QStringLiteral("<p style='color:gray'>No Chrome-family browser profiles with extensions were found yet. "
                                  "Add a user data directory in Settings if your browser lives somewhere unusual.</p>");
    } else {
        welcome += QStringLiteral("<p style='color:gray'>Watching <b>%1</b> extensions across <b>%2</b> profiles. "
                                  "Every version is archived; silent updates are diffed and scored the moment they land.</p>")
                       .arg(extensions).arg(profiles);
        if (m_unacknowledged > 0) {
            welcome += QStringLiteral("<p><b>%1 unreviewed change%2</b>: %3</p>")
                           .arg(m_unacknowledged).arg(m_unacknowledged == 1 ? QString() : QStringLiteral("s"), recent.join(QStringLiteral(", ")));
        } else {
            welcome += QStringLiteral("<p>No unreviewed changes. Select an extension to see its permissions, risk profile and archived versions.</p>");
        }
    }
    m_welcome->setText(welcome);
    updateStatus();
}

void MainWindow::selectExtensionItem(qint64 extensionRowId) {
    for (int g = 0; g < m_tree->topLevelItemCount(); ++g) {
        QTreeWidgetItem* group = m_tree->topLevelItem(g);
        for (int i = 0; i < group->childCount(); ++i) {
            if (group->child(i)->data(0, Qt::UserRole).toLongLong() == extensionRowId) {
                m_tree->blockSignals(true);
                m_tree->setCurrentItem(group->child(i));
                m_tree->blockSignals(false);
                return;
            }
        }
    }
}

void MainWindow::onSelectionChanged() {
    QTreeWidgetItem* item = m_tree->currentItem();
    if (!item || !item->data(0, Qt::UserRole).isValid()) {
        m_stack->setCurrentWidget(m_welcome);
        return;
    }
    openExtension(item->data(0, Qt::UserRole).toLongLong());
}

void MainWindow::openExtension(qint64 extensionRowId) {
    if (m_detail->extensionRowId() != extensionRowId) {
        m_detail->showExtension(extensionRowId);
    }
    m_stack->setCurrentWidget(m_detail);
    selectExtensionItem(extensionRowId);
}

void MainWindow::openEvent(qint64 eventId) {
    const std::optional<EventRow> ev = m_db.eventById(eventId);
    if (!ev) {
        return;
    }
    m_detail->showExtension(ev->extensionId, eventId);
    m_stack->setCurrentWidget(m_detail);
    selectExtensionItem(ev->extensionId);
    show();
    raise();
    activateWindow();
}

void MainWindow::applyFilter(const QString& text) {
    const QString needle = text.trimmed();
    for (int g = 0; g < m_tree->topLevelItemCount(); ++g) {
        QTreeWidgetItem* group = m_tree->topLevelItem(g);
        int visible = 0;
        for (int i = 0; i < group->childCount(); ++i) {
            QTreeWidgetItem* item = group->child(i);
            const bool match = needle.isEmpty() || item->text(0).contains(needle, Qt::CaseInsensitive) ||
                               item->toolTip(0).contains(needle, Qt::CaseInsensitive);
            item->setHidden(!match);
            if (match) {
                visible++;
            }
        }
        group->setHidden(visible == 0);
    }
}

void MainWindow::setWatchStatus(const QString& status) {
    m_watchStatus = status;
    updateStatus();
}

void MainWindow::updateStatus() {
    QStringList parts;
    if (m_lastScan.isValid()) {
        parts << QStringLiteral("%1 extensions in %2 profiles").arg(m_extensionCount).arg(m_profileCount);
        parts << QStringLiteral("last scan %1").arg(m_lastScan.toLocalTime().toString(QStringLiteral("HH:mm:ss")));
    }
    if (!m_watchStatus.isEmpty()) {
        parts << m_watchStatus;
    }
    if (m_unacknowledged > 0) {
        parts << QStringLiteral("%1 unreviewed").arg(m_unacknowledged);
    }
    parts << (m_companionConnections > 0
                  ? QStringLiteral("companion: %1 connected").arg(m_companionConnections)
                  : QStringLiteral("companion: not connected"));
    m_status->setText(parts.isEmpty() ? QStringLiteral("Waiting for the first scan…") : parts.join(QStringLiteral(" · ")));
}

void MainWindow::setCompanionStatus(int connections, const QStringList& browsers) {
    m_companionConnections = connections;
    m_companionBrowsers = browsers;
    m_detail->setCompanionConnected(connections > 0);
    updateStatus();
}

void MainWindow::showActionResult(const QString& title, const QString& text, bool warning) {
    if (warning) {
        QMessageBox::warning(this, title, text);
    } else {
        QMessageBox::information(this, title, text);
    }
}

void MainWindow::selectDetailTab(int index) {
    m_detail->setCurrentTab(index);
}

void MainWindow::openSettings() {
    SettingsDialog dialog(m_dataDir, this);
    connect(&dialog, &SettingsDialog::settingsChanged, this, &MainWindow::settingsChanged);
    dialog.exec();
}

}  // namespace extwatch
