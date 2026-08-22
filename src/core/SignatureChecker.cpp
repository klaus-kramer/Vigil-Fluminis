// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "SignatureChecker.h"

#include <QFileInfo>

#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <winerror.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

QString SignatureResult::statusText() const
{
    switch (status) {
    case NotChecked:    return QStringLiteral("Not checked");
    case Verified:      return QStringLiteral("Verified");
    case Unsigned:      return QStringLiteral("Unsigned");
    case SelfSigned:    return QStringLiteral("Self-Signed");
    case Expired:       return QStringLiteral("Expired");
    case Revoked:       return QStringLiteral("Revoked");
    case UntrustedRoot: return QStringLiteral("Untrusted");
    case Error:         return QStringLiteral("Error");
    }
    return QStringLiteral("Unknown");
}

QString SignatureResult::statusTooltip() const
{
    QString tip;
    switch (status) {
    case NotChecked:    tip = QStringLiteral("Click 'Check Signatures' to scan"); break;
    case Verified:      tip = QStringLiteral("Digitally signed and trusted"); break;
    case Unsigned:      tip = QStringLiteral("No digital signature"); break;
    case SelfSigned:    tip = QStringLiteral("Self-signed certificate, not trusted"); break;
    case Expired:       tip = QStringLiteral("Certificate has expired"); break;
    case Revoked:       tip = QStringLiteral("Certificate has been revoked"); break;
    case UntrustedRoot: tip = QStringLiteral("Certificate chain cannot be verified"); break;
    case Error:         tip = QStringLiteral("Could not check signature"); break;
    }
    if (!publisher.isEmpty())
        tip += QStringLiteral("\nPublisher: %1").arg(publisher);
    tip += QStringLiteral("\n%1").arg(details);
    return tip;
}

static QString win32ErrorText(LONG hr)
{
    wchar_t buf[512] = {};
    DWORD len = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf, ARRAYSIZE(buf), nullptr);
    while (len > 0 && (buf[len - 1] == L'\r' || buf[len - 1] == L'\n'))
        --len;
    return len > 0 ? QString::fromWCharArray(buf, len) : QString();
}

static SignatureResult::Status mapWinVerifyError(LONG status)
{
    switch (status) {
    case ERROR_SUCCESS:                       return SignatureResult::Verified;
    case TRUST_E_NOSIGNATURE:                 return SignatureResult::Unsigned;
    case CERT_E_UNTRUSTEDROOT:                return SignatureResult::UntrustedRoot;
    case CERT_E_UNTRUSTEDTESTROOT:            return SignatureResult::UntrustedRoot;
    case TRUST_E_EXPLICIT_DISTRUST:           return SignatureResult::Revoked;
    case CERT_E_REVOKED:                      return SignatureResult::Revoked;
    case CERT_E_EXPIRED:                      return SignatureResult::Expired;
    case TRUST_E_CERT_SIGNATURE:              return SignatureResult::UntrustedRoot;
    case CRYPT_E_SIGNER_NOT_FOUND:            return SignatureResult::Unsigned;
    case CRYPT_E_NOT_FOUND:                   return SignatureResult::Unsigned;
    case TRUST_E_BAD_DIGEST:                  return SignatureResult::UntrustedRoot;
    case CERT_E_CHAINING:                     return SignatureResult::UntrustedRoot;
    case CERT_E_WRONG_USAGE:                  return SignatureResult::UntrustedRoot;
    case CERT_E_INVALID_NAME:                 return SignatureResult::UntrustedRoot;
    case CERT_E_INVALID_POLICY:               return SignatureResult::UntrustedRoot;
    case CERT_E_ISSUERCHAINING:               return SignatureResult::UntrustedRoot;
    case CERT_E_MALFORMED:                    return SignatureResult::UntrustedRoot;
    case CERT_E_PATHLENCONST:                 return SignatureResult::UntrustedRoot;
    case CRYPT_E_SECURITY_SETTINGS:           return SignatureResult::UntrustedRoot;
    case CRYPT_E_REVOKED:                     return SignatureResult::Revoked;
    case CRYPT_E_NO_REVOCATION_CHECK:         return SignatureResult::Verified;
    case TRUST_E_SUBJECT_FORM_UNKNOWN:        return SignatureResult::Error;
    case TRUST_E_PROVIDER_UNKNOWN:            return SignatureResult::Error;
    case TRUST_E_SUBJECT_NOT_TRUSTED:         return SignatureResult::Error;
    case CRYPT_E_FILE_ERROR:                  return SignatureResult::Error;
    default:
        if (HRESULT_FACILITY(status) == FACILITY_WIN32) {
            LONG win32 = HRESULT_CODE(status);
            switch (win32) {
            case ERROR_FILE_NOT_FOUND:
            case ERROR_PATH_NOT_FOUND:        return SignatureResult::Error;
            case ERROR_ACCESS_DENIED:         return SignatureResult::Error;
            case ERROR_SHARING_VIOLATION:     return SignatureResult::Error;
            case ERROR_LOCK_VIOLATION:        return SignatureResult::Error;
            case ERROR_BAD_FORMAT:            return SignatureResult::Error;
            default:                          return SignatureResult::Error;
            }
        }
        return SignatureResult::Error;
    }
}

static QString getPublisherName(const QString &filePath)
{
    std::wstring widePath = filePath.toStdWString();

    HCERTSTORE store = nullptr;
    HCRYPTMSG msg = nullptr;
    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            widePath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            nullptr,
            nullptr,
            nullptr,
            &store,
            &msg,
            nullptr))
        return {};

    QString publisher;

    PCCERT_CONTEXT certContext = nullptr;
    while ((certContext = CertEnumCertificatesInStore(store, certContext)) != nullptr) {
        wchar_t name[256] = {};
        DWORD nameSize = CertGetNameStringW(
            certContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nullptr,
            name,
            ARRAYSIZE(name));
        if (nameSize > 1) {
            publisher = QString::fromWCharArray(name, nameSize - 1);
            break;
        }
    }

    if (certContext)
        CertFreeCertificateContext(certContext);
    if (store) CertCloseStore(store, 0);
    if (msg) CryptMsgClose(msg);

    return publisher;
}

static bool verifyWithCatalogs(const QString &filePath, QString *publisher)
{
    const std::wstring widePath = filePath.toStdWString();

    HANDLE file = CreateFileW(widePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;

    bool verified = false;

    GUID adminAction = DRIVER_ACTION_VERIFY;
    HCATADMIN catAdmin = nullptr;
    if (CryptCATAdminAcquireContext(&catAdmin, &adminAction, 0)) {
        DWORD hashSize = 0;
        if (CryptCATAdminCalcHashFromFileHandle(file, &hashSize, nullptr, 0)
            && hashSize > 0) {
            std::vector<BYTE> hash(hashSize);
            if (CryptCATAdminCalcHashFromFileHandle(file, &hashSize, hash.data(), 0)) {
                HCATINFO prev = nullptr;
                for (;;) {
                    HCATINFO cur = CryptCATAdminEnumCatalogFromHash(
                        catAdmin, hash.data(), hashSize, 0, &prev);
                    if (!cur)
                        break;

                    CATALOG_INFO info = {};
                    info.cbStruct = sizeof(info);
                    LONG status = CRYPT_E_NOT_FOUND;
                    if (CryptCATCatalogInfoFromContext(cur, &info, 0)) {
                        WINTRUST_CATALOG_INFO catData = {};
                        catData.cbStruct = sizeof(catData);
                        catData.pcwszCatalogFilePath = info.wszCatalogFile;
                        catData.pcwszMemberFilePath = widePath.c_str();
                        catData.pcwszMemberTag = L"File";
                        catData.pbCalculatedFileHash = hash.data();
                        catData.cbCalculatedFileHash = hashSize;

                        WINTRUST_DATA wtd = {};
                        wtd.cbStruct = sizeof(wtd);
                        wtd.dwUIChoice = WTD_UI_NONE;
                        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
                        wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
                        wtd.dwStateAction = WTD_STATEACTION_VERIFY;
                        wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
                        wtd.dwUIContext = WTD_UICONTEXT_EXECUTE;
                        wtd.pCatalog = &catData;

                        GUID genericAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                        status = WinVerifyTrust(
                            static_cast<HWND>(INVALID_HANDLE_VALUE),
                            &genericAction,
                            &wtd);

                        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                        WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE),
                                       &genericAction, &wtd);

                        if (status == ERROR_SUCCESS) {
                            verified = true;
                            if (publisher)
                                *publisher = getPublisherName(
                                    QString::fromWCharArray(info.wszCatalogFile));
                        }
                    }

                    if (prev)
                        CryptCATAdminReleaseCatalogContext(catAdmin, prev, 0);
                    prev = cur;

                    if (verified)
                        break;
                }

                if (prev)
                    CryptCATAdminReleaseCatalogContext(catAdmin, prev, 0);
            }
        }
        CryptCATAdminReleaseContext(catAdmin, 0);
    }

    CloseHandle(file);
    return verified;
}

SignatureResult SignatureChecker::check(const QString &filePath)
{
    SignatureResult result;

    if (filePath.isEmpty() || !QFileInfo::exists(filePath)) {
        result.status = SignatureResult::Error;
        result.details = QStringLiteral("File not found");
        return result;
    }

    std::wstring widePath = filePath.toStdWString();

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = widePath.c_str();
    fileInfo.hFile = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    WINTRUST_DATA wtd = {};
    wtd.cbStruct = sizeof(WINTRUST_DATA);
    wtd.pPolicyCallbackData = nullptr;
    wtd.pSIPClientData = nullptr;
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.hWVTStateData = nullptr;
    wtd.pwszURLReference = nullptr;
    wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    wtd.dwUIContext = WTD_UICONTEXT_EXECUTE;

    GUID genericAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG trustStatus = WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &genericAction,
        &wtd);

    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &genericAction, &wtd);

    result.status = mapWinVerifyError(trustStatus);

    if (result.status == SignatureResult::Unsigned) {
        QString catalogPublisher;
        if (verifyWithCatalogs(filePath, &catalogPublisher)) {
            result.status = SignatureResult::Verified;
            result.publisher = catalogPublisher;
            result.details = catalogPublisher.isEmpty()
                ? QStringLiteral("Signature verified via security catalog")
                : QStringLiteral("Signed by: %1 (security catalog)").arg(catalogPublisher);
            return result;
        }
    }

    if (result.status == SignatureResult::Verified) {
        result.publisher = getPublisherName(filePath);
        if (!result.publisher.isEmpty())
            result.details = QStringLiteral("Signed by: %1").arg(result.publisher);
        else
            result.details = QStringLiteral("Signature verified");
    } else if (result.status == SignatureResult::Unsigned) {
        result.details = QStringLiteral("No digital signature found");
    } else {
        QString text = win32ErrorText(trustStatus);
        if (text.isEmpty())
            result.details = QStringLiteral("Error 0x%1")
                .arg(static_cast<quint32>(trustStatus), 8, 16, QLatin1Char('0'));
        else
            result.details = QStringLiteral("%1 (0x%2)")
                .arg(text)
                .arg(static_cast<quint32>(trustStatus), 8, 16, QLatin1Char('0'));
    }

    return result;
}
