#include "engine.h"
#include "report.h"
#include "ai_detector.h"
#include "secure_ops.h"
#include "security_hardening.h"
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
#define ID_PIN_BTN 1008

HWND hTargetEdit, hResultsEdit, hReportsList;
HWND hTargetLabel, hResultsLabel, hReportsLabel, hPinBtn;  // Add pin button
HINSTANCE hInst;
HFONT hFont, hBoldFont;
BOOL isPinned = FALSE;

void ensure_reports_dir(void) {
    if (is_ghost_mode()) {
        return;  // Skip directory creation in ghost mode - no artifacts
    }
    CreateDirectoryA("reports", NULL);
}

void update_results_display(const char* text) {
    // Simple text display - no emoji replacement needed since we removed all emojis
    int len = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    wchar_t* wtext = malloc(len * sizeof(wchar_t));
    if(wtext) {
        MultiByteToWideChar(CP_UTF8, 0, text, -1, wtext, len);
        SetWindowTextW(hResultsEdit, wtext);
        free(wtext);
    }
}

void toggle_pin_window(HWND hwnd) {
    isPinned = !isPinned;
    
    if(isPinned) {
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        SetWindowTextW(hPinBtn, L"Unpin");
    } else {
        SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        SetWindowTextW(hPinBtn, L"Pin");
    }
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
            strcat(result_text, "[RECON] RECONNAISSANCE RESULTS\r\n");
            strcat(result_text, "================================\r\n\r\n");
            break;
        case 2: // Vuln
            rc = run_vuln(target, &results, &count);
            strcat(result_text, "[VULN] VULNERABILITY SCAN RESULTS\r\n");
            strcat(result_text, "================================\r\n\r\n");
            break;
        case 3: // AI
            rc = run_ai_analysis(target, "scan_data", &results, &count);
            strcat(result_text, "[AI] AI/ML ANALYSIS RESULTS\r\n");
            strcat(result_text, "================================\r\n\r\n");
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
                    strcat(result_text, "[OK] FULL WORKFLOW WITH AI COMPLETED\r\n");
                    strcat(result_text, "====================================\r\n\r\n");
                    strcat(result_text, "Report generated successfully!\r\n");
                    strcat(result_text, "Check the reports list below for details.\r\n\r\n");
                    refresh_reports_list();
                }
                rc = 0;
            }
            break;
    }
    
    if(rc == 0 && results) {
        for(size_t i = 0; i < count && i < 15; i++) { // Limit display for GUI
            char line[300];
            char truncated_data[200];
            
            // Truncate long data for better display
            if(strlen(results[i].data) > 180) {
                strncpy(truncated_data, results[i].data, 180);
                truncated_data[180] = '\0';
                strcat(truncated_data, "...");
            } else {
                strcpy(truncated_data, results[i].data);
            }
            
            snprintf(line, sizeof(line), "-> %s:\r\n   %s\r\n\r\n", 
                     results[i].name, truncated_data);
            strcat(result_text, line);
        }
        if(count > 15) {
            strcat(result_text, "\r\n*** Additional findings available in full report ***\r\n");
            strcat(result_text, "*** Double-click a report file below to view all results ***\r\n");
        }
        free_results(results, count);
    } else if(rc != 0) {
        strcat(result_text, "[FAIL] SCAN FAILED\r\n");
        strcat(result_text, "================\r\n\r\n");
        strcat(result_text, "Please check your target and try again.\r\n");
    }
    
    update_results_display(result_text);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CREATE:
            {
                // Create improved fonts - smaller for compact GUI
                hFont = CreateFont(
                    -12,                        // Smaller height for compact design
                    0,                          // Width
                    0,                          // Escapement
                    0,                          // Orientation
                    FW_NORMAL,                  // Weight
                    FALSE,                      // Italic
                    FALSE,                      // Underline
                    FALSE,                      // StrikeOut
                    ANSI_CHARSET,               // CharSet
                    OUT_DEFAULT_PRECIS,         // OutPrecision
                    CLIP_DEFAULT_PRECIS,        // ClipPrecision
                    CLEARTYPE_QUALITY,          // Quality
                    DEFAULT_PITCH | FF_MODERN,  // Pitch and Family
                    "Segoe UI"                  // More compact font
                );
                
                hBoldFont = CreateFont(
                    -12, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                    ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_MODERN, "Segoe UI"
                );
                
                // Target input with pin button
                hTargetLabel = CreateWindowW(L"STATIC", L"Target:", WS_VISIBLE | WS_CHILD,
                             10, 10, 45, 18, hwnd, NULL, hInst, NULL);
                SendMessage(hTargetLabel, WM_SETFONT, (WPARAM)hBoldFont, TRUE);
                
                hTargetEdit = CreateWindowW(L"EDIT", L"example.com", 
                                          WS_VISIBLE | WS_CHILD | WS_BORDER,
                                          60, 8, 140, 22, hwnd, (HMENU)ID_TARGET_EDIT, hInst, NULL);
                SendMessage(hTargetEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
                
                // Pin button in top right
                hPinBtn = CreateWindowW(L"BUTTON", L"Pin", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                             310, 8, 40, 22, hwnd, (HMENU)ID_PIN_BTN, hInst, NULL);
                SendMessage(hPinBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
                
                // Buttons with compact sizes and simple text
                HWND hReconBtn = CreateWindowW(L"BUTTON", L"Recon", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                             10, 40, 60, 25, hwnd, (HMENU)ID_RECON_BTN, hInst, NULL);
                SendMessage(hReconBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
                
                HWND hVulnBtn = CreateWindowW(L"BUTTON", L"Vuln", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                             80, 40, 60, 25, hwnd, (HMENU)ID_VULN_BTN, hInst, NULL);
                SendMessage(hVulnBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
                
                HWND hAiBtn = CreateWindowW(L"BUTTON", L"AI Scan", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                             150, 40, 60, 25, hwnd, (HMENU)ID_AI_BTN, hInst, NULL);
                SendMessage(hAiBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
                
                HWND hFullBtn = CreateWindowW(L"BUTTON", L"Full+AI", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                             220, 40, 70, 25, hwnd, (HMENU)ID_FULL_BTN, hInst, NULL);
                SendMessage(hFullBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
                
                // Results display - better fill
                hResultsLabel = CreateWindowW(L"STATIC", L"Results:", WS_VISIBLE | WS_CHILD,
                             10, 75, 55, 18, hwnd, NULL, hInst, NULL);
                SendMessage(hResultsLabel, WM_SETFONT, (WPARAM)hBoldFont, TRUE);
                
                hResultsEdit = CreateWindowW(L"EDIT", L"Ready for scanning...\r\n\r\nSelect target and click scan button.", 
                                           WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
                                           10, 95, 350, 180, hwnd, (HMENU)ID_RESULTS_EDIT, hInst, NULL);
                SendMessage(hResultsEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
                
                // Reports list - better fill
                hReportsLabel = CreateWindowW(L"STATIC", L"Reports:", WS_VISIBLE | WS_CHILD,
                             10, 285, 60, 18, hwnd, NULL, hInst, NULL);
                SendMessage(hReportsLabel, WM_SETFONT, (WPARAM)hBoldFont, TRUE);
                
                hReportsList = CreateWindowW(L"LISTBOX", NULL,
                                           WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL,
                                           10, 305, 350, 100, hwnd, (HMENU)ID_REPORTS_LIST, hInst, NULL);
                SendMessage(hReportsList, WM_SETFONT, (WPARAM)hFont, TRUE);
                
                ensure_reports_dir();
                refresh_reports_list();
            }
            break;
            
        case WM_COMMAND:
            switch(LOWORD(wParam)) {
                case ID_PIN_BTN:
                    toggle_pin_window(hwnd);
                    break;
                    
                case ID_RECON_BTN:
                case ID_VULN_BTN:
                case ID_AI_BTN:
                case ID_FULL_BTN:
                    {
                        char target[256];
                        GetWindowTextA(hTargetEdit, target, sizeof(target));
                        
                        // Validate input for security
                        if (!validate_target_input(target)) {
                            MessageBoxA(hwnd, "Invalid target format or potentially malicious input detected.\nPlease enter a valid domain or IP address.", 
                                       "Security Warning", MB_ICONWARNING);
                            break;
                        }
                        
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
            // Cleanup fonts
            if(hFont) DeleteObject(hFont);
            if(hBoldFont) DeleteObject(hBoldFont);
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)lpCmdLine;
    
    // Initialize enterprise security controls
    initialize_security_controls();
    
    // Check professional authorization for organizational use
    if (!check_professional_authorization()) {
        MessageBoxA(NULL, "Professional license required for organizational use.", 
                   "Authorization Required", MB_ICONWARNING);
        secure_organizational_cleanup();
        return 1;
    }
    
    hInst = hInstance;
    
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"SecureScanGUI";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);  // Use application icon instead of shield
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);  // Small icon for taskbar
    
    if(!RegisterClassExW(&wc)) {
        MessageBoxW(NULL, L"Window registration failed!", L"Error", MB_ICONERROR);
        return 0;
    }
    
    HWND hwnd = CreateWindowW(L"SecureScanGUI", L"SecureScan",
                             WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
                             CW_USEDEFAULT, CW_USEDEFAULT,
                             380, 450, NULL, NULL, hInstance, NULL);
    
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
    
    // Secure cleanup before exit (organizational compliance)
    secure_organizational_cleanup();
    return msg.wParam;
}
