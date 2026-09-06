#include "app/extensiondetail.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QPixmap>
#include <QPushButton>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimeZone>
#include <QToolTip>
#include <QTreeWidget>
#include <QVBoxLayout>

#include "app/diffview.h"
#include <QFontDatabase>

#include "core/actions.h"
#include "core/prefs.h"
#include "core/scanner.h"
#include "core/package.h"
#include "core/prettify.h"

namespace extwatch {

namespace {

QString fmtWhen(qint64 secs) {
    if (secs <= 0) {
        return QStringLiteral("-");
    }
    return QDateTime::fromSecsSinceEpoch(secs, QTimeZone::UTC).toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm"));
}

QColor severityColor(const QString& severity) {
    if (severity == QStringLiteral("high")) return QColor(0xe5, 0x48, 0x48);
    if (severity == QStringLiteral("medium")) return QColor(0xe0, 0x8e, 0x1a);
    if (severity == QStringLiteral("low")) return QColor(0x3b, 0x82, 0xf6);
    return QColor(0x8b, 0x93, 0xa7);
}

QString badgeHtml(const QString& text, const QColor& color) {
    return QStringLiteral("<span style=\"background:%1;color:white;border-radius:6px;padding:2px 8px;font-weight:600;font-size:11px;\">%2</span>")
        .arg(color.name(), text.toHtmlEscaped());
}

QString kindLabel(const QString& kind) {
    if (kind == QStringLiteral("baseline")) return QStringLiteral("Baseline");
    if (kind == QStringLiteral("updated")) return QStringLiteral("Updated");
    if (kind == QStringLiteral("pending_version")) return QStringLiteral("Downloaded");
    if (kind == QStringLiteral("enabled")) return QStringLiteral("Enabled");
    if (kind == QStringLiteral("disabled")) return QStringLiteral("Disabled");
    if (kind == QStringLiteral("removed")) return QStringLiteral("Removed");
    if (kind == QStringLiteral("publisher_changed")) return QStringLiteral("Publisher changed");
    if (kind == QStringLiteral("removed_from_store")) return QStringLiteral("Gone from store");
    return kind;
}

}  // namespace

ExtensionDetailView::ExtensionDetailView(QString dataDir, QWidget* parent)
    : QWidget(parent), m_dataDir(std::move(dataDir)), m_blobs(m_dataDir) {
    m_db.open(databasePath(m_dataDir));
    buildUi();
}

void ExtensionDetailView::buildUi() {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 12, 16, 12);
    layout->setSpacing(10);

    // Header
    auto* header = new QHBoxLayout();
    header->setSpacing(14);
    m_icon = new QLabel(this);
    m_icon->setFixedSize(56, 56);
    m_icon->setScaledContents(true);
    header->addWidget(m_icon, 0, Qt::AlignTop);
    auto* titles = new QVBoxLayout();
    titles->setSpacing(2);
    m_name = new QLabel(this);
    QFont nameFont = m_name->font();
    nameFont.setPointSizeF(nameFont.pointSizeF() + 6);
    nameFont.setWeight(QFont::DemiBold);
    m_name->setFont(nameFont);
    m_name->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_meta = new QLabel(this);
    m_meta->setStyleSheet(QStringLiteral("color: palette(mid);"));
    m_meta->setWordWrap(true);
    m_idLabel = new QLabel(this);
    m_idLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    m_idLabel->setFont(mono);
    m_idLabel->setStyleSheet(QStringLiteral("color: palette(mid);"));
    m_badge = new QLabel(this);
    m_badge->setTextFormat(Qt::RichText);
    titles->addWidget(m_name);
    titles->addWidget(m_meta);
    auto* idRow = new QHBoxLayout();
    idRow->addWidget(m_idLabel);
    idRow->addWidget(m_badge);
    idRow->addStretch(1);
    titles->addLayout(idRow);
    header->addLayout(titles, 1);
    layout->addLayout(header);

    // Actions
    auto* actions = new QHBoxLayout();
    actions->setSpacing(8);
    auto* store = new QPushButton(QStringLiteral("Web Store page"), this);
    connect(store, &QPushButton::clicked, this, &ExtensionDetailView::openWebStore);
    auto* copyUrl = new QPushButton(QStringLiteral("Copy extensions page URL"), this);
    copyUrl->setToolTip(QStringLiteral("Browsers block chrome:// links from other apps; paste this into the address bar to disable or remove the extension."));
    connect(copyUrl, &QPushButton::clicked, this, &ExtensionDetailView::copyExtensionsUrl);
    m_folderBtn = new QPushButton(QStringLiteral("Open folder"), this);
    connect(m_folderBtn, &QPushButton::clicked, this, &ExtensionDetailView::openFolder);
    auto* exportBtn = new QPushButton(QStringLiteral("Export version…"), this);
    connect(exportBtn, &QPushButton::clicked, this, &ExtensionDetailView::exportVersion);
    m_quarantineBtn = new QPushButton(QStringLiteral("Quarantine…"), this);
    m_quarantineBtn->setToolTip(QStringLiteral("Move the installed files into the ExtWatch archive so the browser disables the extension as corrupted. Reversible."));
    connect(m_quarantineBtn, &QPushButton::clicked, this, &ExtensionDetailView::quarantine);
    m_restoreBtn = new QPushButton(QStringLiteral("Restore from quarantine"), this);
    connect(m_restoreBtn, &QPushButton::clicked, this, &ExtensionDetailView::restoreFromQuarantine);
    actions->addWidget(store);
    actions->addWidget(copyUrl);
    actions->addWidget(m_folderBtn);
    actions->addWidget(exportBtn);
    actions->addStretch(1);
    m_setupBtn = new QPushButton(QStringLiteral("Set up one-click disable…"), this);
    m_setupBtn->setToolTip(QStringLiteral("Install the companion extension so ExtWatch can disable extensions directly."));
    connect(m_setupBtn, &QPushButton::clicked, this, &ExtensionDetailView::companionSetupRequested);
    m_toggleBtn = new QPushButton(QStringLiteral("Disable"), this);
    connect(m_toggleBtn, &QPushButton::clicked, this, [this]() {
        if (!m_ext) {
            return;
        }
        CompanionServer::Target target;
        target.extId = m_ext->extId;
        target.browserKindId = m_browser ? m_browser->kind : QStringLiteral("chrome");
        for (const ExtensionRow& row : m_db.extensionsForProfile(m_ext->profileId)) {
            target.profileExtensionIds.append(row.extId);
        }
        emit toggleEnabledRequested(target, !m_ext->enabled);
    });
    actions->addWidget(m_setupBtn);
    actions->addWidget(m_toggleBtn);
    actions->addWidget(m_restoreBtn);
    actions->addWidget(m_quarantineBtn);
    layout->addLayout(actions);
    setCompanionConnected(false);

    // Tabs
    m_tabs = new QTabWidget(this);
    m_tabs->setDocumentMode(true);

    // Changes tab: timeline on top, findings below
    auto* changes = new QWidget(this);
    auto* changesLayout = new QVBoxLayout(changes);
    changesLayout->setContentsMargins(0, 8, 0, 0);
    auto* split = new QSplitter(Qt::Vertical, changes);
    m_events = new QTreeWidget(split);
    m_events->setHeaderLabels({QStringLiteral("When"), QStringLiteral("Event"), QStringLiteral("Versions"), QStringLiteral("Severity"), QStringLiteral("What changed")});
    m_events->setRootIsDecorated(false);
    m_events->setAlternatingRowColors(true);
    m_events->header()->setSectionResizeMode(4, QHeaderView::Stretch);
    connect(m_events, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* item, QTreeWidgetItem*) {
        if (item) {
            selectEvent(item->data(0, Qt::UserRole).toLongLong());
        }
    });
    auto* findingsBox = new QWidget(split);
    auto* findingsLayout = new QVBoxLayout(findingsBox);
    findingsLayout->setContentsMargins(0, 6, 0, 0);
    auto* findingsHeader = new QHBoxLayout();
    m_findingsTitle = new QLabel(QStringLiteral("Findings"), findingsBox);
    QFont bold = m_findingsTitle->font();
    bold.setWeight(QFont::DemiBold);
    m_findingsTitle->setFont(bold);
    m_exportReportBtn = new QPushButton(QStringLiteral("Export HTML report…"), findingsBox);
    connect(m_exportReportBtn, &QPushButton::clicked, this, &ExtensionDetailView::exportReport);
    findingsHeader->addWidget(m_findingsTitle, 1);
    findingsHeader->addWidget(m_exportReportBtn);
    findingsLayout->addLayout(findingsHeader);
    m_findings = new QTreeWidget(findingsBox);
    m_findings->setHeaderLabels({QStringLiteral("Severity"), QStringLiteral("Finding"), QStringLiteral("Details"), QStringLiteral("Location")});
    m_findings->setRootIsDecorated(false);
    m_findings->setAlternatingRowColors(true);
    m_findings->setWordWrap(true);
    m_findings->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_findings->setToolTip(QStringLiteral("Double-click a finding to open the code at that line."));
    connect(m_findings, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item, int) { jumpToFinding(item); });
    m_findingDetail = new QLabel(findingsBox);
    m_findingDetail->setWordWrap(true);
    m_findingDetail->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_findingDetail->setStyleSheet(QStringLiteral("padding: 6px 4px; color: palette(text);"));
    m_findingDetail->setText(QStringLiteral("Select a finding for details; double-click to open the code at that line."));
    connect(m_findings, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* item, QTreeWidgetItem*) {
        if (!item || item->text(0).isEmpty()) {
            return;
        }
        QString text = QStringLiteral("<b>%1</b> &nbsp; %2").arg(item->text(1).toHtmlEscaped(), item->text(2).toHtmlEscaped());
        if (!item->text(3).isEmpty()) {
            text += QStringLiteral(" &nbsp; <code>%1</code>").arg(item->text(3).toHtmlEscaped());
        }
        for (const RuleInfo& r : allRules()) {
            if (r.id == item->data(0, Qt::UserRole + 2).toString()) {
                text += QStringLiteral("<br><span style='color:gray'>%1</span>").arg(r.explanation.toHtmlEscaped());
            }
        }
        m_findingDetail->setText(text);
    });
    findingsLayout->addWidget(m_findings, 1);
    findingsLayout->addWidget(m_findingDetail);
    split->addWidget(m_events);
    split->addWidget(findingsBox);
    split->setStretchFactor(0, 1);
    split->setStretchFactor(1, 2);
    changesLayout->addWidget(split);
    m_tabs->addTab(changes, QStringLiteral("Changes"));

    // Manifest tab
    m_manifestDiff = new DiffView(this);
    m_tabs->addTab(m_manifestDiff, QStringLiteral("Manifest"));

    // Code tab
    auto* code = new QSplitter(Qt::Horizontal, this);
    auto* filesBox = new QWidget(code);
    auto* filesLayout = new QVBoxLayout(filesBox);
    filesLayout->setContentsMargins(0, 8, 0, 0);
    m_changedOnly = new QCheckBox(QStringLiteral("Changed files only"), filesBox);
    m_changedOnly->setChecked(true);
    connect(m_changedOnly, &QCheckBox::toggled, this, [this](bool) { populateFiles(); });
    m_files = new QListWidget(filesBox);
    m_files->setFont(mono);
    connect(m_files, &QListWidget::currentItemChanged, this, [this](QListWidgetItem* item, QListWidgetItem*) {
        if (item) {
            showFile(item->data(Qt::UserRole).toString());
        }
    });
    filesLayout->addWidget(m_changedOnly);
    filesLayout->addWidget(m_files, 1);
    m_codeDiff = new DiffView(code);
    code->addWidget(filesBox);
    code->addWidget(m_codeDiff);
    code->setStretchFactor(0, 1);
    code->setStretchFactor(1, 4);
    m_tabs->addTab(code, QStringLiteral("Code"));

    // Versions tab
    m_versions = new QTableWidget(this);
    m_versions->setColumnCount(7);
    m_versions->setHorizontalHeaderLabels({QStringLiteral("Version"), QStringLiteral("First seen"), QStringLiteral("Activated"), QStringLiteral("Files"), QStringLiteral("Size"), QStringLiteral("Tree hash"), QStringLiteral("Signed for ID")});
    m_versions->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    m_versions->verticalHeader()->setVisible(false);
    m_versions->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_versions->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_versions->setToolTip(QStringLiteral("Double-click a version to compare it with the one before it."));
    connect(m_versions, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        const qint64 toId = m_versions->item(row, 0)->data(Qt::UserRole).toLongLong();
        const QVariant fromVar = m_versions->item(row, 0)->data(Qt::UserRole + 1);
        std::optional<qint64> fromId;
        if (fromVar.isValid()) {
            fromId = fromVar.toLongLong();
        }
        if (const std::optional<ChangeReport> r = buildVersionReport(m_db, m_blobs, fromId, toId)) {
            m_eventId.reset();
            showReport(*r);
            m_tabs->setCurrentIndex(0);
        }
    });
    m_tabs->addTab(m_versions, QStringLiteral("Versions"));

    // Signature tab
    m_signature = new QTreeWidget(this);
    m_signature->setHeaderLabels({QStringLiteral("Behavior signature"), QStringLiteral("Where")});
    m_signature->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_tabs->addTab(m_signature, QStringLiteral("Signature"));

    layout->addWidget(m_tabs, 1);
}

void ExtensionDetailView::showExtension(qint64 extensionRowId, std::optional<qint64> eventId) {
    m_extensionId = extensionRowId;
    m_ext = m_db.extensionById(extensionRowId);
    m_profile = m_ext ? m_db.profileById(m_ext->profileId) : std::nullopt;
    m_browser = m_profile ? m_db.browserById(m_profile->browserId) : std::nullopt;
    m_report.reset();
    m_eventId.reset();
    loadHeader();
    loadVersions();
    loadEvents();
    if (eventId) {
        for (int i = 0; i < m_events->topLevelItemCount(); ++i) {
            if (m_events->topLevelItem(i)->data(0, Qt::UserRole).toLongLong() == *eventId) {
                m_events->setCurrentItem(m_events->topLevelItem(i));
                break;
            }
        }
        m_tabs->setCurrentIndex(0);
    } else if (m_events->topLevelItemCount() > 0) {
        m_events->setCurrentItem(m_events->topLevelItem(0));
    }
}

void ExtensionDetailView::setCompanionConnected(bool connected) {
    m_companionConnected = connected;
    m_setupBtn->setVisible(!connected);
    m_toggleBtn->setVisible(connected);
    if (m_ext) {
        m_toggleBtn->setText(m_ext->enabled ? QStringLiteral("Disable") : QStringLiteral("Enable"));
    }
}

void ExtensionDetailView::setCurrentTab(int index) {
    m_tabs->setCurrentIndex(index);
}

void ExtensionDetailView::refresh() {
    if (m_extensionId >= 0) {
        const std::optional<qint64> keep = m_eventId;
        showExtension(m_extensionId, keep);
    }
}

QString ExtensionDetailView::extensionsDir() const {
    if (!m_browser || !m_profile) {
        return {};
    }
    const QString profileDir = m_profile->dirName == QStringLiteral(".")
                                   ? m_browser->userDataDir
                                   : m_browser->userDataDir + u'/' + m_profile->dirName;
    return profileDir + QStringLiteral("/Extensions");
}

QString ExtensionDetailView::versionDirPath(const VersionRow& v) const {
    if (!m_ext) {
        return {};
    }
    return extensionsDir() + u'/' + m_ext->extId + u'/' + v.dirName;
}

std::optional<VersionRow> ExtensionDetailView::currentVersion() {
    if (m_ext && m_ext->currentVersionId) {
        return m_db.versionById(*m_ext->currentVersionId);
    }
    return std::nullopt;
}

QPixmap ExtensionDetailView::loadIcon(const VersionRow& v, const QString& iconPath) {
    if (iconPath.isEmpty()) {
        return {};
    }
    QString wanted = iconPath;
    wanted.replace(u'\\', u'/');
    while (wanted.startsWith(u'/')) {
        wanted.remove(0, 1);
    }
    for (const FileEntry& f : m_db.filesForVersion(v.id)) {
        if (f.relPath == wanted) {
            QPixmap pm(m_blobs.pathFor(f.sha256));
            return pm;
        }
    }
    return {};
}

void ExtensionDetailView::loadHeader() {
    if (!m_ext) {
        return;
    }
    m_name->setText(m_ext->name.isEmpty() ? m_ext->extId : m_ext->name);
    m_idLabel->setText(m_ext->extId);
    const std::optional<VersionRow> current = currentVersion();
    QStringList meta;
    if (m_browser && m_profile) {
        meta << QStringLiteral("%1 / %2").arg(m_browser->displayName, m_profile->displayName);
    }
    if (current) {
        meta << QStringLiteral("version %1").arg(current->version);
    }
    meta << (m_ext->enabled ? QStringLiteral("enabled") : QStringLiteral("disabled"));
    meta << (m_ext->fromWebstore ? QStringLiteral("from the Web Store") : installLocationId(m_ext->location));
    meta << QStringLiteral("watched since %1").arg(fmtWhen(m_ext->firstSeen));
    if (const std::optional<StoreListing> listing = m_db.storeListing(m_ext->extId); listing && listing->found) {
        meta << QStringLiteral("Web Store: offered by %1, store version %2, checked %3")
                    .arg(listing->developer.isEmpty() ? QStringLiteral("?") : listing->developer,
                         listing->version.isEmpty() ? QStringLiteral("?") : listing->version,
                         fmtWhen(listing->fetchedAt));
    }
    m_meta->setText(meta.join(QStringLiteral(" · ")));
    m_toggleBtn->setText(m_ext->enabled ? QStringLiteral("Disable") : QStringLiteral("Enable"));

    QPixmap icon;
    if (current) {
        const std::optional<Signature> sig = signatureForVersion(m_db, m_blobs, current->id);
        if (sig) {
            icon = loadIcon(*current, sig->manifest.iconPath);
        }
    }
    if (icon.isNull()) {
        icon = QPixmap(QStringLiteral(":/app/icons/app.svg"));
    }
    m_icon->setPixmap(icon);

    // Badge: latest non-baseline event, otherwise the baseline profile
    QString badge;
    const QList<EventRow> events = m_db.eventsForExtension(m_ext->id);
    for (auto it = events.crbegin(); it != events.crend(); ++it) {
        if (it->kind != QStringLiteral("baseline") && !it->maxSeverity.isEmpty()) {
            badge = badgeHtml(QStringLiteral("%1 change: %2").arg(kindLabel(it->kind).toLower(), it->maxSeverity), severityColor(it->maxSeverity));
            break;
        }
    }
    if (badge.isEmpty() && !events.isEmpty() && !events.first().maxSeverity.isEmpty()) {
        badge = badgeHtml(QStringLiteral("risk profile: %1").arg(events.first().maxSeverity), severityColor(events.first().maxSeverity));
    }
    m_badge->setText(badge);

    const bool hasFiles = current && QFileInfo(versionDirPath(*current)).isDir();
    m_folderBtn->setEnabled(hasFiles);
    m_quarantineBtn->setEnabled(hasFiles);
    bool restorable = false;
    for (const QuarantineRow& q : m_db.quarantinesForExtension(m_ext->id)) {
        restorable = restorable || q.state != QStringLiteral("restored");
    }
    m_restoreBtn->setVisible(restorable);
}

void ExtensionDetailView::loadEvents() {
    m_events->clear();
    if (!m_ext) {
        return;
    }
    const QList<EventRow> events = m_db.eventsForExtension(m_ext->id);
    for (auto it = events.crbegin(); it != events.crend(); ++it) {
        const EventRow& e = *it;
        auto* item = new QTreeWidgetItem(m_events);
        item->setData(0, Qt::UserRole, e.id);
        item->setText(0, fmtWhen(e.at));
        item->setText(1, kindLabel(e.kind));
        QString versions;
        if (e.fromVersionId) {
            if (const auto v = m_db.versionById(*e.fromVersionId)) versions = v->version + QStringLiteral(" → ");
        }
        if (e.toVersionId) {
            if (const auto v = m_db.versionById(*e.toVersionId)) versions += v->version;
        }
        item->setText(2, versions);
        item->setText(3, e.maxSeverity.isEmpty() ? QString() : e.maxSeverity);
        item->setForeground(3, severityColor(e.maxSeverity));
        QFont f = item->font(3);
        f.setWeight(QFont::DemiBold);
        item->setFont(3, f);
        if (!e.findingsJson.isEmpty()) {
            item->setText(4, findingsSummary(findingsFromJson(QJsonDocument::fromJson(e.findingsJson.toUtf8()).array()), 4));
        }
        if (!e.acknowledged && e.kind != QStringLiteral("baseline")) {
            QFont bold = item->font(1);
            bold.setBold(true);
            item->setFont(1, bold);
        }
    }
    for (int i = 0; i < 4; ++i) {
        m_events->resizeColumnToContents(i);
    }
}

void ExtensionDetailView::selectEvent(qint64 eventId) {
    const std::optional<EventRow> ev = m_db.eventById(eventId);
    if (!ev) {
        return;
    }
    m_eventId = eventId;
    if (!ev->toVersionId) {
        // enabled/disabled/removed: show the current version's report instead
        if (const std::optional<VersionRow> current = currentVersion()) {
            if (const std::optional<ChangeReport> r = buildVersionReport(m_db, m_blobs, std::nullopt, current->id)) {
                showReport(*r);
            }
        }
        return;
    }
    QApplication::setOverrideCursor(Qt::WaitCursor);
    const std::optional<ChangeReport> r = buildChangeReport(m_db, m_blobs, eventId);
    QApplication::restoreOverrideCursor();
    if (r) {
        showReport(*r);
    }
    if (!ev->acknowledged) {
        m_db.acknowledgeEvent(eventId, true);
        emit eventAcknowledged();
    }
}

void ExtensionDetailView::showReport(const ChangeReport& report) {
    m_report = report;
    const QString fromVersion = report.from ? report.from->version : QStringLiteral("nothing");
    m_findingsTitle->setText(report.from
                                 ? QStringLiteral("What changed from %1 to %2").arg(fromVersion, report.to.version)
                                 : QStringLiteral("Risk profile of %1 (first snapshot)").arg(report.to.version));
    m_findings->clear();
    for (const Finding& f : report.findings) {
        auto* item = new QTreeWidgetItem(m_findings);
        item->setText(0, severityId(f.severity).toUpper());
        item->setForeground(0, severityColor(severityId(f.severity)));
        QFont bold = item->font(0);
        bold.setWeight(QFont::DemiBold);
        item->setFont(0, bold);
        item->setText(1, f.title);
        item->setText(2, f.detail);
        item->setToolTip(2, f.detail);
        if (!f.file.isEmpty()) {
            item->setText(3, f.line > 0 ? QStringLiteral("%1:%2").arg(f.file).arg(f.line) : f.file);
        }
        item->setData(0, Qt::UserRole, f.file);
        item->setData(0, Qt::UserRole + 1, f.line);
        item->setData(0, Qt::UserRole + 2, f.rule);
    }
    if (report.findings.isEmpty()) {
        auto* item = new QTreeWidgetItem(m_findings);
        item->setText(1, QStringLiteral("No behavior changes detected"));
    }
    m_findings->resizeColumnToContents(0);
    m_findings->resizeColumnToContents(1);
    m_findings->resizeColumnToContents(3);

    const QString oldManifest = report.fromSignature.manifest.raw.isEmpty()
                                    ? QString()
                                    : QString::fromUtf8(QJsonDocument(report.fromSignature.manifest.raw).toJson(QJsonDocument::Indented));
    const QString newManifest = QString::fromUtf8(QJsonDocument(report.toSignature.manifest.raw).toJson(QJsonDocument::Indented));
    m_manifestDiff->setTexts(oldManifest, newManifest, QStringLiteral("manifest.json · %1").arg(fromVersion),
                             QStringLiteral("manifest.json · %1").arg(report.to.version), true);
    populateFiles();
    loadSignature(report.toSignature);
}

void ExtensionDetailView::populateFiles() {
    m_files->clear();
    if (!m_report) {
        return;
    }
    QListWidgetItem* first = nullptr;
    for (const FileChange& c : m_report->files) {
        if (c.status == FileChange::Status::Unchanged && m_changedOnly->isChecked()) {
            continue;
        }
        QString prefix;
        QColor color;
        switch (c.status) {
            case FileChange::Status::Modified: prefix = QStringLiteral("M  "); color = QColor(0xe0, 0x8e, 0x1a); break;
            case FileChange::Status::Added: prefix = QStringLiteral("A  "); color = QColor(0x2e, 0xa0, 0x43); break;
            case FileChange::Status::Removed: prefix = QStringLiteral("D  "); color = QColor(0xe5, 0x48, 0x48); break;
            case FileChange::Status::Unchanged: prefix = QStringLiteral("   "); break;
        }
        auto* item = new QListWidgetItem(prefix + c.path, m_files);
        item->setData(Qt::UserRole, c.path);
        if (color.isValid()) {
            item->setForeground(color);
        }
        if (!first && c.status != FileChange::Status::Unchanged && c.path != QStringLiteral("manifest.json")) {
            first = item;
        }
    }
    if (m_files->count() == 0) {
        auto* item = new QListWidgetItem(QStringLiteral("no changed files"), m_files);
        item->setFlags(Qt::NoItemFlags);
        m_codeDiff->clear(QStringLiteral("No code files changed between these versions."));
        return;
    }
    m_files->setCurrentItem(first ? first : m_files->item(0));
}

void ExtensionDetailView::showFile(const QString& path) {
    if (!m_report || path.isEmpty()) {
        return;
    }
    QApplication::setOverrideCursor(Qt::WaitCursor);
    const std::optional<QString> oldText = m_report->from ? fileDisplayText(m_db, m_blobs, m_report->from->id, path) : std::nullopt;
    const std::optional<QString> newText = fileDisplayText(m_db, m_blobs, m_report->to.id, path);
    QApplication::restoreOverrideCursor();
    const QString fromVersion = m_report->from ? m_report->from->version : QStringLiteral("nothing");
    m_codeDiff->setTexts(oldText.value_or(QString()), newText.value_or(QString()),
                         QStringLiteral("%1 · %2").arg(path, fromVersion),
                         QStringLiteral("%1 · %2").arg(path, m_report->to.version),
                         isJavaScriptPath(path) || path.endsWith(QStringLiteral(".json")));
}

void ExtensionDetailView::jumpToFinding(QTreeWidgetItem* item) {
    if (!item) {
        return;
    }
    const QString file = item->data(0, Qt::UserRole).toString();
    const int line = item->data(0, Qt::UserRole + 1).toInt();
    if (file.isEmpty()) {
        return;
    }
    const QString path = file.section(u'#', 0, 0);
    m_tabs->setCurrentIndex(2);
    m_changedOnly->setChecked(false);
    for (int i = 0; i < m_files->count(); ++i) {
        if (m_files->item(i)->data(Qt::UserRole).toString() == path) {
            m_files->setCurrentItem(m_files->item(i));
            break;
        }
    }
    if (line > 0) {
        m_codeDiff->jumpToNewLine(line);
    }
}

void ExtensionDetailView::loadVersions() {
    m_versions->setRowCount(0);
    if (!m_ext) {
        return;
    }
    const QList<VersionRow> versions = m_db.versionsForExtension(m_ext->id);
    m_versions->setRowCount(static_cast<int>(versions.size()));
    for (int i = 0; i < versions.size(); ++i) {
        const VersionRow& v = versions.at(versions.size() - 1 - i);  // newest first
        const bool current = m_ext->currentVersionId && *m_ext->currentVersionId == v.id;
        auto* first = new QTableWidgetItem(v.version + (current ? QStringLiteral("  (current)") : QString()));
        first->setData(Qt::UserRole, v.id);
        const qsizetype idx = versions.size() - 1 - i;
        if (idx > 0) {
            first->setData(Qt::UserRole + 1, versions.at(idx - 1).id);
        }
        m_versions->setItem(i, 0, first);
        m_versions->setItem(i, 1, new QTableWidgetItem(fmtWhen(v.firstSeen)));
        m_versions->setItem(i, 2, new QTableWidgetItem(v.activatedAt ? fmtWhen(*v.activatedAt) : QStringLiteral("never")));
        m_versions->setItem(i, 3, new QTableWidgetItem(QString::number(v.fileCount)));
        m_versions->setItem(i, 4, new QTableWidgetItem(QStringLiteral("%1 KiB").arg(v.bytes / 1024)));
        m_versions->setItem(i, 5, new QTableWidgetItem(v.treeHash));
        auto* signed_ = new QTableWidgetItem(v.keyMatchesId ? QStringLiteral("yes") : QStringLiteral("NO"));
        if (!v.keyMatchesId) {
            signed_->setForeground(severityColor(QStringLiteral("high")));
        }
        m_versions->setItem(i, 6, signed_);
    }
    m_versions->resizeColumnsToContents();
    m_versions->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
}

void ExtensionDetailView::loadSignature(const Signature& sig) {
    m_signature->clear();
    auto group = [this](const QString& title, int count) {
        auto* item = new QTreeWidgetItem(m_signature);
        item->setText(0, QStringLiteral("%1 (%2)").arg(title).arg(count));
        QFont bold = item->font(0);
        bold.setWeight(QFont::DemiBold);
        item->setFont(0, bold);
        item->setExpanded(count > 0 && count <= 12);
        return item;
    };
    auto* perms = group(QStringLiteral("Permissions"), static_cast<int>(sig.manifest.permissions.size()));
    for (const QString& p : sig.manifest.permissions) new QTreeWidgetItem(perms, {p});
    QStringList hosts = sig.manifest.hostPermissions;
    for (const ContentScript& cs : sig.manifest.contentScripts) hosts += cs.matches;
    hosts.removeDuplicates();
    auto* hostItem = group(QStringLiteral("Host access"), static_cast<int>(hosts.size()));
    for (const QString& h : hosts) new QTreeWidgetItem(hostItem, {h});
    auto* cs = group(QStringLiteral("Content scripts"), static_cast<int>(sig.manifest.contentScripts.size()));
    for (const ContentScript& c : sig.manifest.contentScripts) {
        new QTreeWidgetItem(cs, {c.js.join(QStringLiteral(", ")) + (c.allFrames ? QStringLiteral("  [all frames]") : QString()) + (c.runAt.isEmpty() ? QString() : QStringLiteral("  [%1]").arg(c.runAt)), c.matches.join(QStringLiteral(", "))});
    }
    auto* domains = group(QStringLiteral("Network domains"), static_cast<int>(sig.domains.size()));
    for (const DomainRef& d : sig.domains) {
        QStringList refs;
        for (const CodeRef& r : d.refs) refs.append(QStringLiteral("%1:%2").arg(r.file).arg(r.line));
        new QTreeWidgetItem(domains, {d.host, refs.mid(0, 4).join(QStringLiteral(", ")) + (refs.size() > 4 ? QStringLiteral(" …") : QString())});
    }
    auto* apis = group(QStringLiteral("chrome.* APIs"), static_cast<int>(sig.chromeApis.size()));
    for (const QString& a : sig.chromeApis) new QTreeWidgetItem(apis, {a});
    auto* sinks = group(QStringLiteral("Code sinks"), static_cast<int>(sig.sinks.size()));
    for (const Sink& s : sig.sinks) new QTreeWidgetItem(sinks, {QStringLiteral("%1  %2").arg(s.kind, s.evidence), QStringLiteral("%1:%2").arg(s.file).arg(s.line)});
    auto* timers = group(QStringLiteral("Timers"), static_cast<int>(sig.timers.size()));
    for (const TimerRef& t : sig.timers) new QTreeWidgetItem(timers, {QStringLiteral("%1 %2 ms%3").arg(t.kind).arg(t.ms).arg(t.stringBody ? QStringLiteral(" (string body!)") : QString()), QStringLiteral("%1:%2").arg(t.file).arg(t.line)});
    auto* listeners = group(QStringLiteral("Page event listeners"), static_cast<int>(sig.listeners.size()));
    for (const ListenerRef& l : sig.listeners) new QTreeWidgetItem(listeners, {l.event, QStringLiteral("%1:%2").arg(l.file).arg(l.line)});
    auto* headers = group(QStringLiteral("Security header modifications"), static_cast<int>(sig.headerMods.size()));
    for (const DnrHeaderMod& h : sig.headerMods) new QTreeWidgetItem(headers, {QStringLiteral("%1 %2").arg(h.operation, h.header), QStringLiteral("ruleset %1, rule %2").arg(h.ruleset).arg(h.ruleId)});
    auto* fp = group(QStringLiteral("Fingerprinting reads"), static_cast<int>(sig.fingerprinting.size()));
    for (const QString& f : sig.fingerprinting) new QTreeWidgetItem(fp, {f, sig.fingerprintingFiles.join(QStringLiteral(", "))});
    auto* obf = group(QStringLiteral("Obfuscation indicators"), sig.obfuscation.total());
    new QTreeWidgetItem(obf, {QStringLiteral("long encoded strings: %1").arg(sig.obfuscation.longBase64Literals)});
    new QTreeWidgetItem(obf, {QStringLiteral("hex-escaped strings: %1").arg(sig.obfuscation.hexEscapedStrings)});
    new QTreeWidgetItem(obf, {QStringLiteral("atob / fromCharCode calls: %1").arg(sig.obfuscation.atobCalls + sig.obfuscation.fromCharCodeCalls)});
    new QTreeWidgetItem(obf, {QStringLiteral("_0x identifiers: %1").arg(sig.obfuscation.obfuscatorIdentifiers)});
    auto* files = group(QStringLiteral("Files"), static_cast<int>(sig.files.size()));
    for (const FileSummary& f : sig.files) new QTreeWidgetItem(files, {f.path, QStringLiteral("%1 B%2").arg(f.bytes).arg(f.parseError ? QStringLiteral("  parse errors") : QString())});
    files->setExpanded(false);
}

void ExtensionDetailView::openWebStore() {
    if (m_ext && m_browser) {
        QDesktopServices::openUrl(webStoreUrl(browserKindFromId(m_browser->kind).value_or(BrowserKind::Chrome), m_ext->extId));
    }
}

void ExtensionDetailView::copyExtensionsUrl() {
    if (!m_ext) {
        return;
    }
    const QString url = extensionsPageUrl(m_browser ? browserKindFromId(m_browser->kind).value_or(BrowserKind::Chrome) : BrowserKind::Chrome, m_ext->extId);
    QApplication::clipboard()->setText(url);
    QToolTip::showText(QCursor::pos(), QStringLiteral("Copied %1\nPaste it into the browser's address bar.").arg(url), this);
}

void ExtensionDetailView::openFolder() {
    if (const std::optional<VersionRow> current = currentVersion()) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(versionDirPath(*current)));
    }
}

void ExtensionDetailView::exportVersion() {
    if (!m_ext) {
        return;
    }
    std::optional<VersionRow> version = currentVersion();
    if (m_report) {
        version = m_report->to;
    }
    if (!version) {
        return;
    }
    const QString suggested = QDir::homePath() + QStringLiteral("/%1-%2.zip").arg(m_ext->extId, version->version);
    const QString target = QFileDialog::getSaveFileName(this, QStringLiteral("Export version %1").arg(version->version), suggested,
                                                        QStringLiteral("Zip archive (*.zip)"));
    if (target.isEmpty()) {
        return;
    }
    QString error;
    if (!writeZip(target, loadSourcesFromArchive(m_db, m_blobs, version->id), &error)) {
        QMessageBox::warning(this, QStringLiteral("Export failed"), error);
        return;
    }
    QMessageBox::information(this, QStringLiteral("Exported"),
                             QStringLiteral("Saved %1 files to %2.\n\nTo run this version: disable the store copy, unzip, open the extensions page, enable Developer mode and choose Load unpacked.")
                                 .arg(version->fileCount).arg(target));
}

void ExtensionDetailView::exportReport() {
    if (!m_report || !m_ext) {
        return;
    }
    const QString suggested = QDir::homePath() + QStringLiteral("/extwatch-%1-%2.html").arg(m_ext->extId, m_report->to.version);
    const QString target = QFileDialog::getSaveFileName(this, QStringLiteral("Export HTML report"), suggested, QStringLiteral("HTML (*.html)"));
    if (target.isEmpty()) {
        return;
    }
    QFile f(target);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::warning(this, QStringLiteral("Export failed"), f.errorString());
        return;
    }
    f.write(renderHtmlReport(m_db, m_blobs, *m_report).toUtf8());
    f.close();
    QDesktopServices::openUrl(QUrl::fromLocalFile(target));
}

void ExtensionDetailView::quarantine() {
    const std::optional<VersionRow> current = currentVersion();
    if (!m_ext || !m_browser || !m_profile || !current) {
        return;
    }
    const QString dir = versionDirPath(*current);
    const auto answer = QMessageBox::question(
        this, QStringLiteral("Quarantine %1?").arg(m_ext->name),
        QStringLiteral("ExtWatch will move\n\n%1\n\ninto its quarantine folder. %2 will report the extension as corrupted "
                       "and disable it; do not choose \"Repair\" there, that re-downloads the same version.\n\n"
                       "Only this browser profile is affected. You can restore the files from this screen. Continue?")
            .arg(dir, m_browser->displayName),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (answer != QMessageBox::Yes) {
        return;
    }
    QuarantineRequest req;
    req.extensionId = m_ext->id;
    req.extId = m_ext->extId;
    req.browserKind = m_browser->kind;
    req.userDataDir = m_browser->userDataDir;
    req.profileDir = m_profile->dirName;
    req.version = current->version;
    req.dirName = current->dirName;
    req.treeHash = current->treeHash;
    req.versionDirPath = dir;
    const ActionResult r = quarantineVersion(m_db, m_dataDir, req);
    if (!r.ok) {
        QMessageBox::warning(this, QStringLiteral("Quarantine failed"), r.message);
        return;
    }
    QMessageBox::information(this, QStringLiteral("Quarantined"), r.message);
    emit inventoryChanged();
    refresh();
}

void ExtensionDetailView::restoreFromQuarantine() {
    if (!m_ext) {
        return;
    }
    QStringList messages;
    bool anyFailure = false;
    for (const QuarantineRow& q : m_db.quarantinesForExtension(m_ext->id)) {
        if (q.state == QStringLiteral("restored")) {
            continue;
        }
        const ActionResult r = restoreQuarantine(m_db, m_dataDir, q.id);
        messages.append(r.message);
        anyFailure = anyFailure || !r.ok;
    }
    if (anyFailure) {
        QMessageBox::warning(this, QStringLiteral("Restore"), messages.join(u'\n'));
    } else {
        QMessageBox::information(this, QStringLiteral("Restored"),
                                 messages.join(u'\n') + QStringLiteral("\n\nRestart the browser to reload the extension."));
    }
    emit inventoryChanged();
    refresh();
}

}  // namespace extwatch
