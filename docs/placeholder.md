# Screenshot Placeholder

The README references `docs/screenshot.png`. Replace this file with a real
screenshot of the running application.

## Recommended dimensions

| Property | Value |
|----------|-------|
| Width    | 1200 px |
| Height   | 750 px  |
| Format   | PNG (lossless) |

## How to take a great screenshot

1. Launch the GUI:
   ```bash
   python fractal_gui.py
   ```
2. Add one or two sample files to the file list (e.g., a PDF and a DOCX).
3. Enter a password — the strength meter should show **Strong** or **Fortress**.
4. Switch to the **Key Visualizer** tab and click **VISUALIZE KEY** so both
   fractal renders are visible.
5. Return to the **Encrypt / Decrypt** tab — the console log should show some
   activity lines.
6. Take the screenshot at 1200 × 750 px.
7. Save as **`docs/screenshot.png`** (overwrite this placeholder).

## Commit the screenshot

```bash
git add docs/screenshot.png
git commit -m "docs: add app screenshot"
git push
```

The README `<img>` tag will automatically display the new screenshot.
