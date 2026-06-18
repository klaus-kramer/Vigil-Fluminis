// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "IpReputationDb.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QRegularExpression>

QVector<IpReputationEntry> IpReputationDb::s_entries;
bool IpReputationDb::s_loaded = false;

struct DefaultEntry {
    const char *cidr;
    const char *label;
    bool isSafe;
};

static const DefaultEntry s_defaults[] = {
    { "8.8.8.0/24",     "Google DNS", true },
    { "8.8.4.0/24",     "Google DNS", true },
    { "1.1.1.0/24",     "Cloudflare DNS", true },
    { "1.0.0.0/24",     "Cloudflare DNS", true },
    { "9.9.9.0/24",     "Quad9 DNS", true },
    { "149.112.112.0/24", "Quad9 DNS", true },
    { "208.67.222.0/24", "OpenDNS", true },
    { "208.67.220.0/24", "OpenDNS", true },
    { "64.6.64.0/18",   "Cisco Umbrella DNS", true },
    { "64.6.64.0/24",   "Cisco Umbrella", true },
    { "199.7.48.0/21",  "ISC F Root", true },
    { "192.5.5.0/24",   "ISC F Root", true },
    { "192.112.36.0/24", "ISC K Root", true },
    { "192.58.128.0/24", "ISC L Root", true },
    { "202.12.27.0/24",  "M Root", true },
    { "193.0.14.0/24",  "RIPE K Root", true },
    { "198.97.190.0/24", "I Root", true },
    { "192.203.230.0/24", "E Root", true },
    { "192.41.162.0/24", "G Root", true },
    { "199.7.83.0/24",  "L Root", true },

    { "13.64.0.0/11",   "Azure", true },
    { "13.96.0.0/13",   "Azure", true },
    { "13.104.0.0/14",  "Azure CDN", true },
    { "20.0.0.0/8",     "Azure / Microsoft", true },
    { "40.74.0.0/15",   "Azure", true },
    { "40.112.0.0/13",  "Azure", true },
    { "40.120.0.0/14",  "Azure", true },
    { "52.96.0.0/14",   "Office 365", true },
    { "52.112.0.0/14",  "Office 365", true },
    { "52.120.0.0/14",  "Office 365", true },
    { "52.238.0.0/15",  "Office 365", true },

    { "173.245.48.0/20", "Cloudflare CDN", true },
    { "103.21.244.0/22", "Cloudflare CDN", true },
    { "103.22.200.0/22", "Cloudflare CDN", true },
    { "103.31.4.0/22",  "Cloudflare CDN", true },
    { "131.0.72.0/22",  "Cloudflare CDN", true },
    { "141.101.64.0/18", "Cloudflare CDN", true },
    { "162.158.0.0/15", "Cloudflare CDN", true },
    { "172.64.0.0/13",  "Cloudflare CDN", true },
    { "188.114.96.0/20", "Cloudflare CDN", true },
    { "190.93.240.0/20", "Cloudflare CDN", true },
    { "197.234.240.0/22", "Cloudflare CDN", true },
    { "198.41.128.0/17", "Cloudflare CDN", true },
    { "104.16.0.0/12",  "Cloudflare CDN", true },

    { "66.249.64.0/19", "Googlebot", true },
    { "64.233.160.0/19", "Google", true },
    { "216.58.192.0/19", "Google", true },
    { "35.190.247.0/24", "Google Cloud", true },
    { "35.191.0.0/16",  "Google Cloud", true },
    { "34.64.0.0/10",   "Google Cloud", true },

    { "52.0.0.0/10",    "AWS", true },
    { "54.192.0.0/10",  "AWS CloudFront", true },
    { "204.246.164.0/22", "AWS CloudFront", true },
    { "205.251.249.0/24", "AWS CloudFront", true },

    { "23.235.128.0/19", "Known Malicious (Spamhaus)", false },
    { "45.42.80.0/20",  "Known Malicious (Spamhaus)", false },
    { "45.74.0.0/16",   "Known Malicious (Spamhaus)", false },
    { "45.140.0.0/16",  "Known Malicious (Spamhaus)", false },
    { "57.14.0.0/15",   "Known Malicious (Spamhaus)", false },
    { "64.15.0.0/20",   "Known Malicious (Spamhaus)", false },
    { "64.250.144.0/20", "Known Malicious (Spamhaus)", false },
    { "69.165.0.0/20",  "Known Malicious (Spamhaus)", false },
    { "71.180.0.0/17",  "Known Malicious (Spamhaus)", false },
    { "80.208.192.0/20", "Known Malicious (Spamhaus)", false },
    { "83.175.0.0/18",  "Known Malicious (Spamhaus)", false },
    { "89.18.0.0/16",   "Known Malicious (Spamhaus)", false },
    { "91.92.240.0/22", "Known Malicious (Spamhaus)", false },
    { "91.188.254.0/24","Known Malicious (Spamhaus)", false },
    { "91.200.164.0/22","Known Malicious (Spamhaus)", false },
    { "91.220.163.0/24","Known Malicious (Spamhaus)", false },
    { "91.229.52.0/22", "Known Malicious (Spamhaus)", false },
    { "91.233.0.0/23",  "Known Malicious (Spamhaus)", false },
    { "92.255.57.0/24", "Known Malicious (Spamhaus)", false },
    { "95.85.238.0/24", "Known Malicious (Spamhaus)", false },
    { "104.244.56.0/21","Known Malicious (Spamhaus)", false },
    { "107.182.240.0/20", "Known Malicious (Spamhaus)", false },
    { "134.122.128.0/17", "Known Malicious (Spamhaus)", false },
    { "138.59.0.0/16",  "Known Malicious (Spamhaus)", false },
    { "147.45.0.0/16",  "Known Malicious (Spamhaus)", false },
    { "149.57.0.0/16",  "Known Malicious (Spamhaus)", false },
    { "162.71.0.0/19",  "Known Malicious (Spamhaus)", false },
    { "167.94.0.0/16",  "Known Malicious (Spamhaus)", false },
    { "168.80.0.0/15",  "Known Malicious (Spamhaus)", false },
    { "176.126.192.0/23","Known Malicious (Spamhaus)", false },
    { "185.14.192.0/24","Known Malicious (Spamhaus)", false },
    { "185.56.83.0/24", "Known Malicious (Spamhaus)", false },
    { "185.110.0.0/22", "Known Malicious (Spamhaus)", false },
    { "185.127.44.0/22","Known Malicious (Spamhaus)", false },
    { "185.212.240.0/22", "Known Malicious (Spamhaus)", false },
    { "192.35.52.0/23", "Known Malicious (Spamhaus)", false },
    { "193.169.0.0/16", "Known Malicious (Spamhaus)", false },
    { "196.16.0.0/14",  "Known Malicious (Spamhaus)", false },
    { "198.20.16.0/20", "Known Malicious (Spamhaus)", false },
    { "198.96.224.0/20","Known Malicious (Spamhaus)", false },
    { "199.33.0.0/16",  "Known Malicious (Spamhaus)", false },
    { "199.127.0.0/16", "Known Malicious (Spamhaus)", false },
    { "204.155.80.0/21","Known Malicious (Spamhaus)", false },
    { "205.210.0.0/16", "Known Malicious (Spamhaus)", false },
    { "206.83.128.0/21","Known Malicious (Spamhaus)", false },
    { "206.221.0.0/16", "Known Malicious (Spamhaus)", false },

    { "45.55.0.0/16",   "DigitalOcean (C2 risk)", false },
    { "68.183.0.0/16",  "DigitalOcean (C2 risk)", false },
    { "95.85.0.0/16",   "DigitalOcean (C2 risk)", false },
    { "104.131.0.0/16", "DigitalOcean (C2 risk)", false },
    { "104.236.0.0/16", "DigitalOcean (C2 risk)", false },
    { "104.248.0.0/16", "DigitalOcean (C2 risk)", false },
    { "107.170.0.0/16", "DigitalOcean (C2 risk)", false },
    { "128.199.0.0/16", "DigitalOcean (C2 risk)", false },
    { "134.122.0.0/16", "DigitalOcean (C2 risk)", false },
    { "134.209.0.0/16", "DigitalOcean (C2 risk)", false },
    { "137.184.0.0/16", "DigitalOcean (C2 risk)", false },
    { "138.68.0.0/16",  "DigitalOcean (C2 risk)", false },
    { "138.197.0.0/16", "DigitalOcean (C2 risk)", false },
    { "142.93.0.0/16",  "DigitalOcean (C2 risk)", false },
    { "143.110.0.0/16", "DigitalOcean (C2 risk)", false },
    { "143.198.0.0/16", "DigitalOcean (C2 risk)", false },
    { "146.190.0.0/16", "DigitalOcean (C2 risk)", false },
    { "147.182.0.0/16", "DigitalOcean (C2 risk)", false },
    { "157.230.0.0/16", "DigitalOcean (C2 risk)", false },
    { "157.245.0.0/16", "DigitalOcean (C2 risk)", false },
    { "159.65.0.0/16",  "DigitalOcean (C2 risk)", false },
    { "159.89.0.0/16",  "DigitalOcean (C2 risk)", false },
    { "159.203.0.0/16", "DigitalOcean (C2 risk)", false },
    { "159.223.0.0/16", "DigitalOcean (C2 risk)", false },
    { "161.35.0.0/16",  "DigitalOcean (C2 risk)", false },
    { "162.243.0.0/16", "DigitalOcean (C2 risk)", false },
    { "164.90.0.0/16",  "DigitalOcean (C2 risk)", false },
    { "165.22.0.0/16",  "DigitalOcean (C2 risk)", false },
    { "165.227.0.0/16", "DigitalOcean (C2 risk)", false },
    { "167.71.0.0/16",  "DigitalOcean (C2 risk)", false },
    { "167.99.0.0/16",  "DigitalOcean (C2 risk)", false },
    { "167.172.0.0/16", "DigitalOcean (C2 risk)", false },
    { "174.138.0.0/17", "DigitalOcean (C2 risk)", false },
    { "178.62.0.0/16",  "DigitalOcean (C2 risk)", false },
    { "178.128.0.0/16", "DigitalOcean (C2 risk)", false },
    { "188.166.0.0/16", "DigitalOcean (C2 risk)", false },
    { "192.241.128.0/17", "DigitalOcean (C2 risk)", false },
    { "198.199.64.0/18", "DigitalOcean (C2 risk)", false },
    { "206.189.0.0/16", "DigitalOcean (C2 risk)", false },
    { "207.154.192.0/18", "DigitalOcean (C2 risk)", false },
    { "209.38.0.0/16",  "DigitalOcean (C2 risk)", false },

    { "5.9.0.0/16",     "Hetzner (C2 risk)", false },
    { "46.4.0.0/16",    "Hetzner (C2 risk)", false },
    { "49.12.0.0/16",   "Hetzner (C2 risk)", false },
    { "49.13.0.0/16",   "Hetzner (C2 risk)", false },
    { "65.21.0.0/16",   "Hetzner (C2 risk)", false },
    { "65.108.0.0/16",  "Hetzner (C2 risk)", false },
    { "78.46.0.0/15",   "Hetzner (C2 risk)", false },
    { "85.10.192.0/18", "Hetzner (C2 risk)", false },
    { "88.198.0.0/16",  "Hetzner (C2 risk)", false },
    { "94.130.0.0/16",  "Hetzner (C2 risk)", false },
    { "95.216.0.0/16",  "Hetzner (C2 risk)", false },
    { "116.202.0.0/16", "Hetzner (C2 risk)", false },
    { "136.243.0.0/16", "Hetzner (C2 risk)", false },
    { "138.201.0.0/16", "Hetzner (C2 risk)", false },
    { "142.132.0.0/16", "Hetzner (C2 risk)", false },
    { "144.76.0.0/16",  "Hetzner (C2 risk)", false },
    { "148.251.0.0/16", "Hetzner (C2 risk)", false },
    { "157.90.0.0/16",  "Hetzner (C2 risk)", false },
    { "159.69.0.0/16",  "Hetzner (C2 risk)", false },
    { "162.55.0.0/16",  "Hetzner (C2 risk)", false },
    { "167.235.0.0/16", "Hetzner (C2 risk)", false },
    { "168.119.0.0/16", "Hetzner (C2 risk)", false },
    { "176.9.0.0/16",   "Hetzner (C2 risk)", false },
    { "188.40.0.0/16",  "Hetzner (C2 risk)", false },
    { "195.201.0.0/16", "Hetzner (C2 risk)", false },
    { "213.133.96.0/19", "Hetzner (C2 risk)", false },
    { "213.239.192.0/18", "Hetzner (C2 risk)", false },
};
static const int s_defaultCount = sizeof(s_defaults) / sizeof(s_defaults[0]);

static quint32 parseIp(const QString &s, bool *ok = nullptr)
{
    QStringList parts = s.split('.');
    if (parts.size() != 4) {
        if (ok) *ok = false;
        return 0;
    }
    quint32 addr = 0;
    for (int i = 0; i < 4; ++i) {
        bool o;
        quint32 byte = parts[i].toUInt(&o);
        if (!o || byte > 255) {
            if (ok) *ok = false;
            return 0;
        }
        addr = (addr << 8) | byte;
    }
    if (ok) *ok = true;
    return addr;
}

static inline quint32 cidrMask(int bits)
{
    if (bits >= 32) return 0xFFFFFFFF;
    if (bits <= 0)  return 0;
    return ~((quint64(1) << (32 - bits)) - 1);
}

void IpReputationDb::writeDefaults(const QString &path)
{
    QJsonObject root;

    auto writeCategory = [&](const char *category, bool isSafe) {
        QJsonArray arr;
        for (int i = 0; i < s_defaultCount; ++i) {
            if (s_defaults[i].isSafe != isSafe)
                continue;
            QJsonObject obj;
            obj[QStringLiteral("cidr")]  = QString::fromUtf8(s_defaults[i].cidr);
            obj[QStringLiteral("label")] = QString::fromUtf8(s_defaults[i].label);
            arr.append(obj);
        }
        root[QString::fromUtf8(category)] = arr;
    };

    writeCategory("safe", true);
    writeCategory("suspicious", false);

    QFile file(path);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text))
        file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
}

void IpReputationDb::ensureLoaded()
{
    if (s_loaded)
        return;
    s_loaded = true;

    QString path = QCoreApplication::applicationDirPath()
        + QStringLiteral("/ip_reputation.json");

    auto parseEntry = [](IpReputationEntry &e) {
        int slash = e.cidr.indexOf('/');
        if (slash < 0) return;
        bool ok;
        e.baseAddr = parseIp(e.cidr.left(slash), &ok);
        if (!ok) return;
        int bits = e.cidr.mid(slash + 1).toInt();
        if (bits < 0 || bits > 32) return;
        e.mask = cidrMask(bits);
        e.baseAddr &= e.mask;
    };

    QFile file(path);
    if (file.open(QIODevice::ReadOnly)) {
        QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
        file.close();
        if (doc.isObject()) {
            const QJsonObject root = doc.object();
            auto loadCategory = [&](bool isSafe) {
                const char *key = isSafe ? "safe" : "suspicious";
                for (const auto &val : root[key].toArray()) {
                    QJsonObject entry = val.toObject();
                    IpReputationEntry e;
                    e.cidr   = entry[QStringLiteral("cidr")].toString();
                    e.label  = entry[QStringLiteral("label")].toString();
                    e.isSafe = isSafe;
                    parseEntry(e);
                    s_entries.append(e);
                }
            };
            loadCategory(true);
            loadCategory(false);
            return;
        }
    }

    writeDefaults(path);
    for (int i = 0; i < s_defaultCount; ++i) {
        IpReputationEntry e;
        e.cidr   = QString::fromUtf8(s_defaults[i].cidr);
        e.label  = QString::fromUtf8(s_defaults[i].label);
        e.isSafe = s_defaults[i].isSafe;
        parseEntry(e);
        s_entries.append(e);
    }
}

IpReputationResult IpReputationDb::checkIp(const QString &ip)
{
    ensureLoaded();

    bool ok;
    quint32 raw = parseIp(ip, &ok);
    if (!ok)
        return { IpReputationResult::Unknown, {} };

    for (const auto &e : s_entries) {
        if ((raw & e.mask) == e.baseAddr) {
            return { e.isSafe ? IpReputationResult::Safe : IpReputationResult::Suspicious,
                     e.label };
        }
    }

    return { IpReputationResult::Unknown, {} };
}
