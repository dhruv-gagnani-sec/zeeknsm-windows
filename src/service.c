/*
 * service.c - Windows Service Wrapper Implementation
 *
 * Architecture:
 *
 *   Console mode (--config):
 *     main() → service_run(run_as_service=false)
 *            → zeek_main_loop()  [blocks until CTRL+C]
 *
 *   Service mode (SCM starts the binary):
 *     main() → service_run(run_as_service=true)
 *            → StartServiceCtrlDispatcher()
 *            → service_main()  [called by SCM on its thread]
 *               → RegisterServiceCtrlHandler()
 *               → report_status(SERVICE_RUNNING)
 *               → zeek_main_loop()  [blocks until SCM sends STOP]
 *               → report_status(SERVICE_STOPPED)
 */

#include "service.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 * Module-level state (valid only during service execution)
 * ============================================================ */
static SERVICE_STATUS        g_status;
static SERVICE_STATUS_HANDLE g_handle;

static volatile bool g_stop    = false;
static char          g_cfg_path[MAX_PATH_LEN];

/* ============================================================
 * Internal: report current service status to the SCM
 * ============================================================ */
static void report_status(DWORD state, DWORD exit_code, DWORD wait_hint) {
    static DWORD checkpoint = 1;

    g_status.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState            = state;
    g_status.dwControlsAccepted        =
        (state == SERVICE_START_PENDING)
        ? 0
        : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_status.dwWin32ExitCode           = exit_code;
    g_status.dwServiceSpecificExitCode = 0;
    g_status.dwCheckPoint              =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED)
        ? 0 : checkpoint++;
    g_status.dwWaitHint                = wait_hint;

    SetServiceStatus(g_handle, &g_status);
}

/* ============================================================
 * Service Control Handler  (called on SCM thread)
 * ============================================================ */
static void WINAPI service_ctrl(DWORD ctrl) {
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        fprintf(stdout, "[service] Received STOP/SHUTDOWN from SCM\n");
        report_status(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        g_stop = true;
        return;
    case SERVICE_CONTROL_INTERROGATE:
        break;   /* fall through — report current state */
    default:
        break;
    }
    report_status(g_status.dwCurrentState, NO_ERROR, 0);
}

/* ============================================================
 * ServiceMain  (entry point called by SCM dispatcher thread)
 * ============================================================ */
static void WINAPI service_main(DWORD argc, LPSTR *argv) {
    (void)argc;
    (void)argv;

    /* Register control handler before doing anything else */
    g_handle = RegisterServiceCtrlHandlerA(SERVICE_NAME, service_ctrl);
    if (!g_handle) {
        fprintf(stderr, "[service] RegisterServiceCtrlHandler failed: %lu\n",
                GetLastError());
        return;
    }

    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    /* Hand off to the monitoring loop */
    report_status(SERVICE_RUNNING, NO_ERROR, 0);
    fprintf(stdout, "[service] Service running\n");

    zeek_main_loop(g_cfg_path, &g_stop);

    report_status(SERVICE_STOPPED, NO_ERROR, 0);
    fprintf(stdout, "[service] Service stopped\n");
}

/* ============================================================
 * service_install
 * ============================================================ */
int service_install(const char *exe_path, const char *cfg_path) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        fprintf(stderr, "[service] OpenSCManager failed: %lu "
                        "(run as Administrator)\n", GetLastError());
        return -1;
    }

    /* Build the binary path that SCM will invoke */
    char bin_path[1024];
    snprintf(bin_path, sizeof(bin_path),
             "\"%s\" --service --config \"%s\"",
             exe_path, cfg_path);

    SC_HANDLE svc = CreateServiceA(
        scm,
        SERVICE_NAME,
        SERVICE_DISPLAY,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,       /* Start on every boot */
        SERVICE_ERROR_NORMAL,
        bin_path,
        NULL, NULL, NULL,
        NULL,                     /* LocalSystem account */
        NULL
    );

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            /* Service exists — update it instead */
            svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
            if (!svc) {
                fprintf(stderr, "[service] OpenService (for update) failed: %lu\n", GetLastError());
                CloseServiceHandle(scm);
                return -1;
            }

            if (!ChangeServiceConfigA(
                svc,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                bin_path,
                NULL, NULL, NULL,
                NULL, NULL, NULL)) 
            {
                fprintf(stderr, "[service] ChangeServiceConfig failed: %lu\n", GetLastError());
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
                return -1;
            }
            fprintf(stdout, "[service] Updated existing service '%s'.\n", SERVICE_NAME);
        } else {
            fprintf(stderr, "[service] CreateService failed: %lu\n", err);
            CloseServiceHandle(scm);
            return -1;
        }
    }

    /* Attach a human-readable description */
    SERVICE_DESCRIPTIONA desc;
    desc.lpDescription = (LPSTR)SERVICE_DESCRIPTION;
    ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    fprintf(stdout,
            "[service] Installed '%s' as auto-start service.\n"
            "          Binary path: %s\n"
            "          Use: sc start %s   (or reboot)\n",
            SERVICE_NAME, bin_path, SERVICE_NAME);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

/* ============================================================
 * service_uninstall
 * ============================================================ */
int service_uninstall(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        fprintf(stderr, "[service] OpenSCManager failed: %lu\n",
                GetLastError());
        return -1;
    }

    SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME,
                                 SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!svc) {
        fprintf(stderr, "[service] OpenService '%s' failed: %lu\n",
                SERVICE_NAME, GetLastError());
        CloseServiceHandle(scm);
        return -1;
    }

    /* Stop the service if it is running */
    SERVICE_STATUS st;
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        fprintf(stdout, "[service] Stopping '%s' ...\n", SERVICE_NAME);
        Sleep(2000);
    }

    if (!DeleteService(svc)) {
        fprintf(stderr, "[service] DeleteService failed: %lu\n",
                GetLastError());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return -1;
    }

    fprintf(stdout, "[service] Service '%s' removed.\n", SERVICE_NAME);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

/* ============================================================
 * service_run
 * ============================================================ */
int service_run(const char *cfg_path, bool run_as_service) {
    /* Store config path so service_main() can reach it */
    strncpy(g_cfg_path, cfg_path ? cfg_path : "", sizeof(g_cfg_path) - 1);

    if (run_as_service) {
        /* Hand control to the SCM dispatcher. This call BLOCKS until all
         * service threads return.  If we are NOT running under the SCM
         * (console invocation with --service), the dispatcher returns
         * ERROR_FAILED_SERVICE_CONTROLLER_CONNECT — fall through to
         * console mode in that case. */
        SERVICE_TABLE_ENTRYA table[] = {
            { (LPSTR)SERVICE_NAME,
              (LPSERVICE_MAIN_FUNCTIONA)service_main },
            { NULL, NULL }
        };

        if (!StartServiceCtrlDispatcherA(table)) {
            DWORD err = GetLastError();
            if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                fprintf(stdout,
                        "[service] Not started by SCM — "
                        "running in console mode.\n");
                /* Fall through to console loop below */
            } else {
                fprintf(stderr,
                        "[service] StartServiceCtrlDispatcher failed: %lu\n",
                        err);
                return -1;
            }
        } else {
            /* Dispatcher returned normally — service has stopped */
            return 0;
        }
    }

    /* ---- Console / direct mode ---- */
    return zeek_main_loop(cfg_path, &g_stop);
}
