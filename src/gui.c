#include "engine.h"
#include "report.h"
#include "ai_detector.h"
#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>

#define ID_TARGET_EDIT 1001
#define ID_RECON_BTN 1002
#define ID_VULN_BTN 1003
#define ID_AI_BTN 1004
#define ID_FULL_BTN 1005
#define ID_RESULTS_EDIT 1006
#define ID_REPORTS_LIST 1007

HWND hTargetEdit, hResultsEdit, hReportsList;
HINSTANCE hInst;

void ensure_reports_dir(void) {
    CreateDirectoryA("reports", NULL);
}

void update_results_display(const char* text) {
    int len = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    wchar_t* wtext = malloc(len * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, text, -1, wtext, len);
    SetWindowTextW(hResultsEdit, wtext);
    free(wtext);
}

void refresh_reports_list(void) {
    SendMessage(hReportsList, LB_RESETCONTENT, 0, 0);
    
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(L"reports\\*_summary.md", &findData);
    
    if(hFind != INVALID_HANDLE_VALUE) {
        do {
            SendMessageW(hReportsList, LB_ADDSTRING, 0, (LPARAM)findData.cFileName);
        } while(FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
}

void run_scan_module(int module_type, const char* target) {
    char result_text[4096] = {0};
    module_result_t *results = NULL;
    size_t count = 0;
    
    int rc = -1;
    switch(module_type) {
        case 1: // Recon
            rc = run_recon(target, &results, &count);
            strcat(result_text, "🔍 RECONNAISSANCE RESULTS\n\n");
            break;
        case 2: // Vuln
            rc = run_vuln(target, &results, &count);
            strcat(result_text, "🛡️ VULNERABILITY SCAN RESULTS\n\n");
            break;
        case 3: // AI
            rc = run_ai_analysis(target, "scan_data", &results, &count);
            strcat(result_text, "🤖 AI/ML ANALYSIS RESULTS\n\n");
            break;
        case 4: // Full
            {
                module_result_t *recon = NULL, *vuln = NULL, *ai_results = NULL;
                size_t recon_count = 0, vuln_count = 0, ai_count = 0;
                
                run_recon(target, &recon, &recon_count);
                run_vuln(target, &vuln, &vuln_count);
                run_ai_analysis(target, "scan_data", &ai_results, &ai_count);
                
                count = recon_count + vuln_count + ai_count;
                results = calloc(count, sizeof(module_result_t));
                if(results) {
                    for(size_t i = 0; i < recon_count; i++) results[i] = recon[i];
                    for(size_t j = 0; j < vuln_count; j++) results[recon_count + j] = vuln[j];
                    for(size_t k = 0; k < ai_count; k++) results[recon_count + vuln_count + k] = ai_results[k];
                    free(recon); free(vuln); free(ai_results);
                    
                    ensure_reports_dir();
                    run_report(results, count, target);
                    strcat(result_text, "✅ FULL WORKFLOW WITH AI COMPLETED\n\n");
                    refresh_reports_list();
                }
                rc = 0;
            }
            break;
    }
    
    if(rc == 0 && results) {
        for(size_t i = 0; i < count && i < 20; i++) { // Limit display for GUI
            char line[256];
            snprintf(line, sizeof(line), "• %s: %.100s...\n", results[i].name, results[i].data);
            strcat(result_text, line);
        }
        if(count > 20) {
            strcat(result_text, "\n... (see full report for complete results)\n");
        }
        free_results(results, count);
    } else {
        strcat(result_text, "❌ Scan failed\n");
    }
    
    update_results_display(result_text);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CREATE:
            {
                // Target input
                CreateWindowW(L"STATIC", L"Target:", WS_VISIBLE | WS_CHILD,
                             10, 10, 60, 20, hwnd, NULL, hInst, NULL);
                hTargetEdit = CreateWindowW(L"EDIT", L"example.com", 
                                          WS_VISIBLE | WS_CHILD | WS_BORDER,
                                          80, 10, 200, 25, hwnd, (HMENU)ID_TARGET_EDIT, hInst, NULL);
                
                // Buttons
                CreateWindowW(L"BUTTON", L"🔍 Recon", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                             10, 50, 75, 30, hwnd, (HMENU)ID_RECON_BTN, hInst, NULL);
                CreateWindowW(L"BUTTON", L"🛡️ Vuln Scan", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                             95, 50, 75, 30, hwnd, (HMENU)ID_VULN_BTN, hInst, NULL);
                CreateWindowW(L"BUTTON", L"🤖 AI Analysis", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                             180, 50, 75, 30, hwnd, (HMENU)ID_AI_BTN, hInst, NULL);
                CreateWindowW(L"BUTTON", L"⚡ Full+AI", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                             265, 50, 75, 30, hwnd, (HMENU)ID_FULL_BTN, hInst, NULL);
                
                // Results display
                CreateWindowW(L"STATIC", L"Results:", WS_VISIBLE | WS_CHILD,
                             10, 95, 60, 20, hwnd, NULL, hInst, NULL);
                hResultsEdit = CreateWindowW(L"EDIT", L"Ready for AI-powered scanning...", 
                                           WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
                                           10, 120, 420, 200, hwnd, (HMENU)ID_RESULTS_EDIT, hInst, NULL);
                
                // Reports list
                CreateWindowW(L"STATIC", L"Generated Reports:", WS_VISIBLE | WS_CHILD,
                             10, 335, 120, 20, hwnd, NULL, hInst, NULL);
                hReportsList = CreateWindowW(L"LISTBOX", NULL,
                                           WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL,
                                           10, 360, 420, 100, hwnd, (HMENU)ID_REPORTS_LIST, hInst, NULL);
                
                ensure_reports_dir();
                refresh_reports_list();
            }
            break;
            
        case WM_COMMAND:
            switch(LOWORD(wParam)) {
                case ID_RECON_BTN:
                case ID_VULN_BTN:
                case ID_AI_BTN:
                case ID_FULL_BTN:
                    {
                        char target[256];
                        GetWindowTextA(hTargetEdit, target, sizeof(target));
                        
                        int module = LOWORD(wParam) - ID_RECON_BTN + 1;
                        run_scan_module(module, target);
                    }
                    break;
                    
                case ID_REPORTS_LIST:
                    if(HIWORD(wParam) == LBN_DBLCLK) {
                        int sel = SendMessage(hReportsList, LB_GETCURSEL, 0, 0);
                        if(sel != LB_ERR) {
                            wchar_t filename[MAX_PATH];
                            SendMessageW(hReportsList, LB_GETTEXT, sel, (LPARAM)filename);
                            
                            wchar_t path[MAX_PATH];
                            swprintf(path, MAX_PATH, L"reports\\%s", filename);
                            ShellExecuteW(NULL, L"open", path, NULL, NULL, SW_SHOWNORMAL);
                        }
                    }
                    break;
            }
            break;
            
        case WM_CLOSE:
            DestroyWindow(hwnd);
            break;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)lpCmdLine;
    
    hInst = hInstance;
    
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"PenTestGUI";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    if(!RegisterClassW(&wc)) {
        MessageBoxW(NULL, L"Window registration failed!", L"Error", MB_ICONERROR);
        return 0;
    }
    
    HWND hwnd = CreateWindowW(L"PenTestGUI", L"🔒 AI-Powered PenTest Automation Toolkit",
                             WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                             460, 520, NULL, NULL, hInstance, NULL);
    
    if(!hwnd) {
        MessageBoxW(NULL, L"Window creation failed!", L"Error", MB_ICONERROR);
        return 0;
    }
    
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    MSG msg;
    while(GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return msg.wParam;
}
