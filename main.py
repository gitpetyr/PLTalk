#!/usr/bin/env python3
"""
PLTalk — Entry point (PyWebview Edition).

Usage:
  python main.py
  PLTALK_PROFILE=alice python main.py
"""
import sys
import os
import webview

sys.path.insert(0, os.path.dirname(__file__))

from ui_bridge import ApiBridge


if __name__ == "__main__":
    bridge = ApiBridge()

    # Create the web view Window pointing to our static index.html
    html_path = os.path.join(os.path.dirname(__file__), "ui_web", "index.html")
    window = webview.create_window(
        "PLTalk (NPCP P2P Chat)", 
        url="file://" + html_path,
        js_api=bridge,
        width=960, 
        height=640,
        min_size=(720, 480),
        frameless=False, # Alternatively True if you implement custom drag regions completely
        background_color="#f5f5f5"
    )
    
    bridge.set_window(window)

    def on_closed():
        bridge.shutdown()
        import time
        time.sleep(0.5)
        os._exit(0)
    
    window.events.closed += on_closed

    # Start the application loop
    webview.start(debug=False)
