using System;
using System.Drawing;
using System.Windows.Forms;
using System.IO;
using System.Collections.Generic;
using System.Linq;

namespace ArtemisSecurity
{
    public static class ArtemisVision
    {
        private static readonly string ScreenshotDirectory = Path.Combine(Environment.CurrentDirectory, "C:\\Users\\Danie\\Desktop\\Artemis\\bin\\Debug\\tool_screenshots");

        public static void CaptureAndAnalyzeScreen()
        {
            var screenshot = CaptureScreen();
            SaveScreenshot(screenshot);
            CompareWithKnownTools(screenshot);
        }

        private static Bitmap CaptureScreen()
        {
            Rectangle bounds = Screen.PrimaryScreen.Bounds;
            Bitmap screenshot = new Bitmap(bounds.Width, bounds.Height);
            using (Graphics g = Graphics.FromImage(screenshot))
            {
                g.CopyFromScreen(Point.Empty, Point.Empty, bounds.Size);
            }
            return screenshot;
        }

        private static void SaveScreenshot(Bitmap screenshot)
        {
            if (!Directory.Exists(ScreenshotDirectory))
            {
                Directory.CreateDirectory(ScreenshotDirectory);
            }

            string fileName = $"Screenshot_{DateTime.Now:yyyyMMdd_HHmmss}.png";
            string filePath = Path.Combine(ScreenshotDirectory, fileName);
            screenshot.Save(filePath);
        }

        private static void CompareWithKnownTools(Bitmap currentScreenshot)
        {
            var knownToolScreenshots = Directory.GetFiles(ScreenshotDirectory, "KnownTool_*.png");
            
            foreach (var toolScreenshot in knownToolScreenshots)
            {
                using (var knownTool = new Bitmap(toolScreenshot))
                {
                    if (CompareImages(currentScreenshot, knownTool))
                    {
                        Console.WriteLine($"Potential RE tool detected! Matches known tool: {Path.GetFileNameWithoutExtension(toolScreenshot)}");
                        // Add more actions here, such as logging or triggering an alert
                    }
                }
            }
        }

        private static bool CompareImages(Bitmap img1, Bitmap img2)
        {
            if (img1.Size != img2.Size)
                return false;

            for (int i = 0; i < img1.Width; i++)
            {
                for (int j = 0; j < img1.Height; j++)
                {
                    if (img1.GetPixel(i, j) != img2.GetPixel(i, j))
                    {
                        return false;
                    }
                }
            }

            return true;
        }
    }
}