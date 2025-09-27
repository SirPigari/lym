#ifdef _WIN32
#include <windows.h>
#include <stddef.h>
#define EXPORT __declspec(dllexport)
#elif __APPLE__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define EXPORT __attribute__((visibility("default")))
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define EXPORT __attribute__((visibility("default")))
#endif

// MSGBOX style flags
#define MSGBOX_OK 0x0000
#define MSGBOX_OKCANCEL 0x0001
#define MSGBOX_ABORTRETRYIGNORE 0x0002
#define MSGBOX_YESNOCANCEL 0x0003
#define MSGBOX_YESNO 0x0004
#define MSGBOX_RETRYCANCEL 0x0005
#define MSGBOX_CANCELTRYCONTINUE 0x0006

#define MSGBOX_ICONHAND 0x0010
#define MSGBOX_ICONQUESTION 0x0020
#define MSGBOX_ICONEXCLAMATION 0x0030
#define MSGBOX_ICONASTERISK 0x0040

#define MSGBOX_USERICON 0x0080
#define MSGBOX_ICONWARNING MSGBOX_ICONEXCLAMATION
#define MSGBOX_ICONERROR MSGBOX_ICONHAND
#define MSGBOX_ICONINFORMATION MSGBOX_ICONASTERISK
#define MSGBOX_ICONSTOP MSGBOX_ICONHAND

#define MSGBOX_DEFBUTTON1 0x0000
#define MSGBOX_DEFBUTTON2 0x0100
#define MSGBOX_DEFBUTTON3 0x0200
#define MSGBOX_DEFBUTTON4 0x0300

#define MSGBOX_APPLMODAL 0x0000
#define MSGBOX_SYSTEMMODAL 0x1000
#define MSGBOX_TASKMODAL 0x2000

#define MSGBOX_HELP 0x4000
#define MSGBOX_NOFOCUS 0x8000
#define MSGBOX_SETFOREGROUND 0x10000
#define MSGBOX_DEFAULTDESKTOPONLY 0x20000
#define MSGBOX_TOPMOST 0x40000
#define MSGBOX_RIGHT 0x80000
#define MSGBOX_RTLREADING 0x100000

#define MSGBOX_TYPEMASK 0x000F
#define MSGBOX_ICONMASK 0x00F0

// Return constants aligned with Windows IDOK
#define MSGBOX_RET_OK 1
#define MSGBOX_RET_CANCEL 2
#define MSGBOX_RET_ABORT 3
#define MSGBOX_RET_RETRY 4
#define MSGBOX_RET_IGNORE 5
#define MSGBOX_RET_YES 6
#define MSGBOX_RET_NO 7
#define MSGBOX_RET_CLOSE 8
#define MSGBOX_RET_HELP 9
#define MSGBOX_RET_TRYAGAIN 10
#define MSGBOX_RET_CONTINUE 11

EXPORT int show_message_box(const char *title, const char *message, int style_flags)
{
#ifdef _WIN32
    UINT type = MB_SETFOREGROUND;

    switch (style_flags & MSGBOX_TYPEMASK)
    {
    case MSGBOX_OK:
        type |= MB_OK;
        break;
    case MSGBOX_OKCANCEL:
        type |= MB_OKCANCEL;
        break;
    case MSGBOX_ABORTRETRYIGNORE:
        type |= MB_ABORTRETRYIGNORE;
        break;
    case MSGBOX_YESNOCANCEL:
        type |= MB_YESNOCANCEL;
        break;
    case MSGBOX_YESNO:
        type |= MB_YESNO;
        break;
    case MSGBOX_RETRYCANCEL:
        type |= MB_RETRYCANCEL;
        break;
    case MSGBOX_CANCELTRYCONTINUE:
        type |= MB_CANCELTRYCONTINUE;
        break;
    default:
        type |= MB_OK;
        break;
    }

    switch (style_flags & MSGBOX_ICONMASK)
    {
    case MSGBOX_ICONHAND:
        type |= MB_ICONHAND;
        break;
    case MSGBOX_ICONQUESTION:
        type |= MB_ICONQUESTION;
        break;
    case MSGBOX_ICONEXCLAMATION:
        type |= MB_ICONEXCLAMATION;
        break;
    case MSGBOX_ICONASTERISK:
        type |= MB_ICONASTERISK;
        break;
    }

    if (style_flags & MSGBOX_SYSTEMMODAL)
        type |= MB_SYSTEMMODAL;
    if (style_flags & MSGBOX_TASKMODAL)
        type |= MB_TASKMODAL;
    if (style_flags & MSGBOX_HELP)
        type |= MB_HELP;
    if (style_flags & MSGBOX_NOFOCUS)
        type |= MB_NOFOCUS;
    if (style_flags & MSGBOX_SETFOREGROUND)
        type |= MB_SETFOREGROUND;
    if (style_flags & MSGBOX_DEFAULTDESKTOPONLY)
        type |= MB_DEFAULT_DESKTOP_ONLY;
    if (style_flags & MSGBOX_TOPMOST)
        type |= MB_TOPMOST;
    if (style_flags & MSGBOX_RIGHT)
        type |= MB_RIGHT;
    if (style_flags & MSGBOX_RTLREADING)
        type |= MB_RTLREADING;

    return MessageBoxA(NULL, message, title, type);

#elif __APPLE__
    // Map buttons and capture result from osascript via pipe
    // Compose AppleScript
    const char *buttons = "buttons {\"OK\"}";
    const char *default_button = "default button \"OK\"";
    const char *cancel_button = "";
    const char *icon = "note";

    switch (style_flags & MSGBOX_TYPEMASK)
    {
    case MSGBOX_OKCANCEL:
        buttons = "buttons {\"OK\", \"Cancel\"}";
        default_button = "default button \"OK\"";
        cancel_button = "cancel button \"Cancel\"";
        break;
    case MSGBOX_YESNO:
        buttons = "buttons {\"Yes\", \"No\"}";
        default_button = "default button \"Yes\"";
        cancel_button = "cancel button \"No\"";
        break;
    case MSGBOX_YESNOCANCEL:
        buttons = "buttons {\"Yes\", \"No\", \"Cancel\"}";
        default_button = "default button \"Yes\"";
        cancel_button = "cancel button \"Cancel\"";
        break;
    case MSGBOX_ABORTRETRYIGNORE:
        buttons = "buttons {\"Abort\", \"Retry\", \"Ignore\"}";
        default_button = "default button \"Retry\"";
        cancel_button = "cancel button \"Abort\"";
        break;
    case MSGBOX_RETRYCANCEL:
        buttons = "buttons {\"Retry\", \"Cancel\"}";
        default_button = "default button \"Retry\"";
        cancel_button = "cancel button \"Cancel\"";
        break;
    case MSGBOX_CANCELTRYCONTINUE:
        buttons = "buttons {\"Cancel\", \"Try\", \"Continue\"}";
        default_button = "default button \"Try\"";
        cancel_button = "cancel button \"Cancel\"";
        break;
    default:
        buttons = "buttons {\"OK\"}";
        default_button = "default button \"OK\"";
        cancel_button = "";
        break;
    }

    switch (style_flags & MSGBOX_ICONMASK)
    {
    case MSGBOX_ICONERROR:
        icon = "stop";
        break;
    case MSGBOX_ICONWARNING:
        icon = "caution";
        break;
    case MSGBOX_ICONQUESTION:
        icon = "note";
        break;
    case MSGBOX_ICONINFORMATION:
        icon = "note";
        break;
    default:
        icon = "note";
        break;
    }

    // Build AppleScript to get button clicked
    char script[2048];
    snprintf(script, sizeof(script),
             "osascript -e 'try' "
             "-e 'set result to button returned of (display dialog \"%s\" with title \"%s\" with icon %s %s %s)' "
             "-e 'on error number -128' " // user cancelled
             "-e 'return \"CANCEL\"' "
             "-e 'end try' "
             "-e 'return result'",
             message, title, icon, buttons, default_button);

    FILE *fp = popen(script, "r");
    if (!fp)
        return 0;

    char buf[64];
    if (!fgets(buf, sizeof(buf), fp))
    {
        pclose(fp);
        return 0;
    }
    pclose(fp);

    buf[strcspn(buf, "\r\n")] = 0;

    // Map button string to return code
    if (strcmp(buf, "OK") == 0)
        return MSGBOX_RET_OK;
    else if (strcmp(buf, "Yes") == 0)
        return MSGBOX_RET_YES;
    else if (strcmp(buf, "No") == 0)
        return MSGBOX_RET_NO;
    else if (strcmp(buf, "Cancel") == 0)
        return MSGBOX_RET_CANCEL;
    else if (strcmp(buf, "Abort") == 0)
        return MSGBOX_RET_ABORT;
    else if (strcmp(buf, "Retry") == 0)
        return MSGBOX_RET_RETRY;
    else if (strcmp(buf, "Ignore") == 0)
        return MSGBOX_RET_IGNORE;
    else if (strcmp(buf, "Try") == 0)
        return MSGBOX_RET_TRYAGAIN;
    else if (strcmp(buf, "Continue") == 0)
        return MSGBOX_RET_CONTINUE;
    else if (strcmp(buf, "CANCEL") == 0)
        return MSGBOX_RET_CANCEL;
    else
        return 0;

#else
    // Linux: zenity/kdialog/xmessage

    const char *btn = "";
    const char *icon = "--info";

    switch (style_flags & MSGBOX_TYPEMASK)
    {
    case MSGBOX_OK:
        btn = "";
        break;
    case MSGBOX_OKCANCEL:
        btn = "--ok-label=OK --cancel-label=Cancel";
        break;
    case MSGBOX_YESNO:
        btn = "--ok-label=Yes --cancel-label=No";
        break;
    case MSGBOX_YESNOCANCEL:
        btn = "--ok-label=Yes --cancel-label=No";
        break; // zenity no 3 button support
    case MSGBOX_ABORTRETRYIGNORE:
    case MSGBOX_RETRYCANCEL:
    case MSGBOX_CANCELTRYCONTINUE:
        btn = "--ok-label=OK"; // fallback to simple OK button
        break;
    default:
        btn = "";
        break;
    }

    switch (style_flags & MSGBOX_ICONMASK)
    {
    case MSGBOX_ICONERROR:
        icon = "--error";
        break;
    case MSGBOX_ICONWARNING:
        icon = "--warning";
        break;
    case MSGBOX_ICONQUESTION:
        icon = "--question";
        break;
    case MSGBOX_ICONINFORMATION:
        icon = "--info";
        break;
    default:
        icon = "--info";
        break;
    }

    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "if command -v zenity >/dev/null 2>&1; then "
             "zenity %s %s --title=\"%s\" --text=\"%s\"; "
             "elif command -v kdialog >/dev/null 2>&1; then "
             "kdialog --msgbox \"%s\" --title \"%s\"; "
             "elif command -v xmessage >/dev/null 2>&1; then "
             "xmessage -center \"%s\"; "
             "else echo \"%s\"; fi",
             icon, btn, title, message,
             message, title,
             message,
             message);

    int ret = system(cmd);

    // Map system return codes:
    // zenity/kdialog return 0 on OK, 1 on cancel/error
    // xmessage always 0 (can't detect button)
    if (ret == 0)
    {
        // Treat OK/Yes as MSGBOX_RET_OK or MSGBOX_RET_YES depending on style
        switch (style_flags & MSGBOX_TYPEMASK)
        {
        case MSGBOX_YESNO:
        case MSGBOX_YESNOCANCEL:
            return MSGBOX_RET_YES;
        default:
            return MSGBOX_RET_OK;
        }
    }
    else
    {
        // Cancel/No
        switch (style_flags & MSGBOX_TYPEMASK)
        {
        case MSGBOX_YESNO:
        case MSGBOX_YESNOCANCEL:
            return MSGBOX_RET_NO;
        default:
            return MSGBOX_RET_CANCEL;
        }
    }

#endif
}
