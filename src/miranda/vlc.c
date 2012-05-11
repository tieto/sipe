#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <vlc/vlc.h>

extern HINSTANCE hInst;

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch(msg)
    {
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

int __stdcall show_vlc(void *data)
{
     libvlc_instance_t * inst;
     libvlc_media_player_t *mp;
     libvlc_media_t *m;
	int rc;
	HANDLE w;
	WNDCLASSEX wc;
     
     /* Load the VLC engine */
     inst = libvlc_new (0, NULL);
  
     /* Create a new item */
     m = libvlc_media_new_path (inst, "C:\\Temp\\[001_1-01] Broken Bow (Part 1).mpg");
        
     /* Create a media player playing environement */
     mp = libvlc_media_player_new_from_media (m);
     
     /* No need to keep the media now */
     libvlc_media_release (m);
 

	//Step 1: Registering the Window Class
	wc.cbSize        = sizeof(WNDCLASSEX);
	wc.style         = 0;
	wc.lpfnWndProc   = WndProc;
	wc.cbClsExtra    = 0;
	wc.cbWndExtra    = 0;
	wc.hInstance     = hInst;
	wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
	wc.lpszMenuName  = NULL;
	wc.lpszClassName = L"myclassstuff";
	wc.hIconSm       = LoadIcon(NULL, IDI_APPLICATION);

	if(!RegisterClassEx(&wc))
	{
		MessageBox(NULL, L"Window Registration Failed!", L"Error!", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}
  
	w = CreateWindow(L"myclassstuff", L"VLC Window", WS_OVERLAPPEDWINDOW, 50, 50, 400, 400, NULL, NULL, hInst, NULL);

	if (!w)
	{
		DWORD d = GetLastError();
		printf ("===================== %08x ==============\n", d);

	}

//	libvlc_media_player_set_hwnd (mp, w);

//	ShowWindow(w, SW_SHOW); 
//	UpdateWindow(w); 

#if 0
     /* This is a non working code that show how to hooks into a window,
      * if we have a window around */
      libvlc_media_player_set_xdrawable (mp, xdrawable);
     /* or on windows */
     /* or on mac os */
      libvlc_media_player_set_nsobject (mp, view);
#endif
 
     /* play the media_player */
     rc = libvlc_media_player_play (mp);
    
     Sleep (60000); /* Let it play a bit */
    
     /* Stop playing */
     libvlc_media_player_stop (mp);
 
     /* Free the media_player */
     libvlc_media_player_release (mp);
 
     libvlc_release (inst);
 
     return 0;
}
