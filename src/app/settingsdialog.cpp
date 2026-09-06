#include "app/settingsdialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QUrl>
#include <QVBoxLayout>

#include "app/appsettings.h"
#include "core/autostart.h"

namespace extwatch {

SettingsDialog::SettingsDialog(const QString& dataDir, QWidget* parent)
    : QDialog(parent), m_dataDir(dataDir) {
    setWindowTitle(QStringLiteral("ExtWatch Settings"));
    setMinimumWidth(520);
    auto* layout = new QVBoxLayout(this);
    auto* form = new QFormLayout();
    form->setLabelAlignment(Qt::AlignRight);

    m_autostart = new QCheckBox(QStringLiteral("Start ExtWatch when I log in"), this);
    m_autostart->setChecked(isAutostartEnabled());
    form->addRow(QStringLiteral("Startup"), m_autostart);

    m_threshold = new QComboBox(this);
    m_threshold->addItems({QStringLiteral("Every change"), QStringLiteral("Low severity and above"),
                           QStringLiteral("Medium severity and above"), QStringLiteral("High severity only")});
    m_threshold->setCurrentIndex(AppSettings::notifyThreshold());
    form->addRow(QStringLiteral("Notify me about"), m_threshold);

    m_interval = new QSpinBox(this);
    m_interval->setRange(1, 24 * 60);
    m_interval->setSuffix(QStringLiteral(" min"));
    m_interval->setValue(AppSettings::rescanIntervalMinutes());
    m_interval->setToolTip(QStringLiteral("File changes are picked up immediately; this is the safety-net full rescan."));
    form->addRow(QStringLiteral("Full rescan every"), m_interval);

    m_extraDirs = new QPlainTextEdit(this);
    m_extraDirs->setPlaceholderText(QStringLiteral("chrome=/path/to/User Data\nbrave=/another/User Data"));
    m_extraDirs->setPlainText(AppSettings::extraUserDataDirs().join(u'\n'));
    m_extraDirs->setFixedHeight(80);
    form->addRow(QStringLiteral("Extra user data dirs"), m_extraDirs);

    m_trackPublisher = new QCheckBox(QStringLiteral("Check the Web Store listing daily for publisher changes"), this);
    m_trackPublisher->setChecked(AppSettings::trackPublisher());
    m_trackPublisher->setToolTip(QStringLiteral("Sends the IDs of your store-installed extensions to chromewebstore.google.com once a day."
                                                " Off by default because it is the only network access ExtWatch ever makes."));
    form->addRow(QStringLiteral("Publisher tracking"), m_trackPublisher);

    auto* dataRow = new QHBoxLayout();
    auto* dataLabel = new QLabel(m_dataDir, this);
    dataLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    dataLabel->setWordWrap(true);
    auto* openData = new QPushButton(QStringLiteral("Open"), this);
    connect(openData, &QPushButton::clicked, this, [this]() {
        QDesktopServices::openUrl(QUrl::fromLocalFile(m_dataDir));
    });
    dataRow->addWidget(dataLabel, 1);
    dataRow->addWidget(openData);
    form->addRow(QStringLiteral("Archive"), dataRow);

    layout->addLayout(form);
    auto* note = new QLabel(QStringLiteral("Everything stays on this computer. The only optional network access is the daily Web Store check above."), this);
    note->setWordWrap(true);
    note->setStyleSheet(QStringLiteral("color: palette(mid);"));
    layout->addWidget(note);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &SettingsDialog::save);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);
}

void SettingsDialog::save() {
    QString error;
    if (m_autostart->isChecked() != isAutostartEnabled() &&
        !setAutostartEnabled(m_autostart->isChecked(), &error)) {
        QMessageBox::warning(this, QStringLiteral("Autostart"),
                             QStringLiteral("Could not change the login item: %1").arg(error));
    }
    AppSettings::setNotifyThreshold(m_threshold->currentIndex());
    AppSettings::setTrackPublisher(m_trackPublisher->isChecked());
    AppSettings::setRescanIntervalMinutes(m_interval->value());
    QStringList dirs;
    for (const QString& line : m_extraDirs->toPlainText().split(u'\n')) {
        if (!line.trimmed().isEmpty()) {
            dirs.append(line.trimmed());
        }
    }
    AppSettings::setExtraUserDataDirs(dirs);
    emit settingsChanged();
    accept();
}

}  // namespace extwatch
