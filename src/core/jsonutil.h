#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QStringList>

namespace extwatch {

// Strings in a JSON array; non-string entries are dropped.
inline QStringList toStringList(const QJsonValue& value) {
    QStringList out;
    if (!value.isArray()) {
        return out;
    }
    for (const QJsonValue& v : value.toArray()) {
        if (v.isString()) {
            out.append(v.toString());
        }
    }
    return out;
}

inline QJsonArray fromStringList(const QStringList& list) {
    QJsonArray out;
    for (const QString& s : list) {
        out.append(s);
    }
    return out;
}

}  // namespace extwatch
