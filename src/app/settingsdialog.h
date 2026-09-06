#pragma once

#include <QDialog>

class QCheckBox;
class QComboBox;
class QPlainTextEdit;
class QSpinBox;

namespace extwatch {

class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(const QString& dataDir, QWidget* parent = nullptr);

signals:
    void settingsChanged();

private:
    void save();

    QString m_dataDir;
    QCheckBox* m_autostart = nullptr;
    QCheckBox* m_trackPublisher = nullptr;
    QComboBox* m_threshold = nullptr;
    QSpinBox* m_interval = nullptr;
    QPlainTextEdit* m_extraDirs = nullptr;
};

}  // namespace extwatch
