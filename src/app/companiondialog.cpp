#include "app/companiondialog.h"

#include <QApplication>
#include <QClipboard>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QUrl>
#include <QVBoxLayout>

#include "app/companionserver.h"
#include "core/companion.h"
#include "core/discovery.h"

namespace extwatch {

CompanionDialog::CompanionDialog(const QString& dataDir, CompanionServer* server, QWidget* parent)
    : QDialog(parent), m_dataDir(dataDir), m_server(server) {
    setWindowTitle(QStringLiteral("Companion extension"));
    setMinimumWidth(560);
    auto* layout = new QVBoxLayout(this);

    auto* intro = new QLabel(this);
    intro->setWordWrap(true);
    intro->setText(QStringLiteral(
        "<p>The companion is a tiny extension (about 150 lines, <code>management</code> and "
        "<code>nativeMessaging</code> permissions only) that lets ExtWatch <b>disable an extension with one click</b> "
        "and hear about installs and updates the moment they happen. Monitoring stays outside the browser; only this "
        "switch lives inside it.</p>"
        "<ol><li>Click <b>Register and open folder</b>. ExtWatch registers its native messaging host for every browser "
        "found on this computer (no admin rights) and copies the extension files to its data folder.</li>"
        "<li>In the browser, open <code>chrome://extensions</code> (or <code>brave://extensions</code>, "
        "<code>edge://extensions</code>), turn on <b>Developer mode</b>, click <b>Load unpacked</b> and choose that folder. "
        "Repeat for each browser profile you want to control.</li></ol>"));
    layout->addWidget(intro);

    auto* row = new QHBoxLayout();
    auto* registerBtn = new QPushButton(QStringLiteral("Register and open folder"), this);
    connect(registerBtn, &QPushButton::clicked, this, &CompanionDialog::registerAndOpen);
    auto* copyBtn = new QPushButton(QStringLiteral("Copy chrome://extensions"), this);
    connect(copyBtn, &QPushButton::clicked, this, []() {
        QApplication::clipboard()->setText(QStringLiteral("chrome://extensions"));
    });
    row->addWidget(registerBtn);
    row->addWidget(copyBtn);
    row->addStretch(1);
    layout->addLayout(row);

    m_folder = new QLabel(this);
    m_folder->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_folder->setWordWrap(true);
    layout->addWidget(m_folder);

    m_log = new QPlainTextEdit(this);
    m_log->setReadOnly(true);
    m_log->setFixedHeight(120);
    layout->addWidget(m_log);

    m_status = new QLabel(this);
    layout->addWidget(m_status);
    connect(m_server, &CompanionServer::connectionsChanged, this, &CompanionDialog::refreshStatus);
    refreshStatus();

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);
}

void CompanionDialog::registerAndOpen() {
    QList<BrowserInstall> installs;
    for (const DiscoveredBrowser& b : discoverBrowsers(knownBrowserLocations())) {
        installs.append(b.install);
    }
    m_log->clear();
    if (installs.isEmpty()) {
        m_log->appendPlainText(QStringLiteral("No browsers found."));
    }
    for (const HostRegistration& r : registerNativeHost(QCoreApplication::applicationFilePath(), m_dataDir, installs)) {
        m_log->appendPlainText(QStringLiteral("%1 %2: %3").arg(r.ok ? QStringLiteral("✓") : QStringLiteral("✗"),
                                                              browserKindName(r.kind), r.ok ? r.location : r.error));
    }
    QString error;
    const QString folder = extractCompanion(m_dataDir, &error);
    if (folder.isEmpty()) {
        m_log->appendPlainText(QStringLiteral("✗ could not write the companion files: %1").arg(error));
        return;
    }
    m_folder->setText(QStringLiteral("Load unpacked from: <b>%1</b>").arg(folder.toHtmlEscaped()));
    m_log->appendPlainText(QStringLiteral("Companion extension ID: %1").arg(companionExtensionId()));
    QDesktopServices::openUrl(QUrl::fromLocalFile(folder));
}

void CompanionDialog::refreshStatus() {
    const int n = m_server->connectionCount();
    if (n == 0) {
        m_status->setText(QStringLiteral("<span style='color:gray'>No companion connected yet.</span>"));
    } else {
        m_status->setText(QStringLiteral("<b style='color:#2ea043'>Connected:</b> %1 browser profile(s) (%2)")
                              .arg(n)
                              .arg(m_server->connectedBrowsers().join(QStringLiteral(", "))));
    }
}

}  // namespace extwatch
