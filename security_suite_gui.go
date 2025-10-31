package main

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// GUILogMessage represents a GUI log message (to avoid confusion with types.go LogMessage if it exists there)
type GUILogMessage struct {
	Level string
	Text  string
}

// SecuritySuiteInterface holds the Fyne GUI components
type SecuritySuiteInterface struct {
	window       fyne.Window
	controller   *CoreController
	logChannel   chan GUILogMessage
	logHistory   []GUILogMessage
	logWidget    *widget.RichText
	statusLabels map[string]*widget.Label
}

// NewSecuritySuiteInterface initializes the GUI
func NewSecuritySuiteInterface(c *CoreController, logCh chan LogMessage) *SecuritySuiteInterface {
	a := app.New()
	a.Settings().SetTheme(theme.DarkTheme())

	// Convert LogMessage channel to GUILogMessage channel
	guiLogCh := make(chan GUILogMessage, 100)
	go func() {
		for msg := range logCh {
			guiLogCh <- GUILogMessage{
				Level: msg.Level,
				Text:  msg.Text,
			}
		}
	}()

	gui := &SecuritySuiteInterface{
		window:       a.NewWindow("Advanced Security Suite Dashboard"),
		controller:   c,
		logChannel:   guiLogCh,
		logHistory:   make([]GUILogMessage, 0),
		statusLabels: make(map[string]*widget.Label),
	}

	gui.window.Resize(fyne.NewSize(1024, 768))
	gui.setupUI()
	gui.startLogReader()

	return gui
}

// setupUI constructs the main window layout
func (s *SecuritySuiteInterface) setupUI() {
	// Control Panel
	scanButton := widget.NewButtonWithIcon("Execute Scan", theme.SearchIcon(), func() {
		s.controller.ExecuteScan("file", "/opt/security_suite_targets", 3)
		s.logChannel <- GUILogMessage{"INFO", "Manual scan initiated on /opt/security_suite_targets."}
	})

	updateButton := widget.NewButtonWithIcon("Update Definitions", theme.DownloadIcon(), func() {
		status, err := s.controller.UpdateDefinitions()
		if err != nil {
			s.logChannel <- GUILogMessage{"ERROR", fmt.Sprintf("Definition update failed: %s", err.Error())}
		} else {
			s.logChannel <- GUILogMessage{"INFO", fmt.Sprintf("Definition update successful. New status: %s", status)}
		}
	})

	stopButton := widget.NewButtonWithIcon("Stop Services", theme.MediaStopIcon(), func() {
		s.controller.StopAllServices()
		s.logChannel <- GUILogMessage{"ALERT", "All background services STOPPED by user action."}
	})

	controls := container.NewHBox(scanButton, updateButton, stopButton, layout.NewSpacer())

	// Status Panel
	s.statusLabels["Health"] = widget.NewLabel("Health: Initializing...")
	s.statusLabels["IDS"] = widget.NewLabel("IDS: Offline")
	s.statusLabels["Malware"] = widget.NewLabel("Malware: Offline")
	s.statusLabels["Behavioral"] = widget.NewLabel("Behavioral: Offline")

	statusGrid := container.New(layout.NewGridLayout(4),
		s.statusLabels["Health"],
		s.statusLabels["IDS"],
		s.statusLabels["Malware"],
		s.statusLabels["Behavioral"],
	)

	// Log Panel
	s.logWidget = widget.NewRichTextWithText("Security Suite Log History goes here.")
	s.logWidget.Wrapping = fyne.TextWrapBreak
	logPanel := container.NewScroll(s.logWidget)

	// Tabs
	scanTab := container.NewVBox(
		widget.NewLabel("Scan Results (To be implemented with table view)"),
		widget.NewLabel("Latest Scan: N/A"),
	)

	rulesTab := container.NewVBox(
		widget.NewLabel("IDS/YARA Rule Status (To be implemented with list view)"),
		widget.NewLabel("Rules Version: Unknown"),
	)

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Dashboard", theme.HomeIcon(), container.NewVBox(statusGrid, controls, layout.NewSpacer())),
		container.NewTabItemWithIcon("Scans", theme.DocumentIcon(), scanTab),
		container.NewTabItemWithIcon("Rules", theme.SettingsIcon(), rulesTab),
	)

	// Main content layout
	mainContent := container.NewVSplit(
		tabs,
		logPanel,
	)
	mainContent.SetOffset(0.7)

	s.window.SetContent(mainContent)

	// Start status updater
	go s.startStatusUpdater()
}

// startStatusUpdater periodically queries the CoreController for status
func (s *SecuritySuiteInterface) startStatusUpdater() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		status := s.controller.GetSystemStatus()

		s.statusLabels["Health"].SetText(fmt.Sprintf("Health: %s", status.OverallHealth))
		s.statusLabels["IDS"].SetText(fmt.Sprintf("IDS: Rules v%s", status.RuleManager.RulesVersion))
		s.statusLabels["Malware"].SetText(fmt.Sprintf("Malware: Engine v%s", status.MalwareEngine.EngineVersion))
		s.statusLabels["Behavioral"].SetText(fmt.Sprintf("Behavioral: Model v%s", status.BehavioralAnalyzer.ModelVersion))

		s.window.Canvas().Refresh(s.statusLabels["Health"])
		s.window.Canvas().Refresh(s.statusLabels["IDS"])
		s.window.Canvas().Refresh(s.statusLabels["Malware"])
		s.window.Canvas().Refresh(s.statusLabels["Behavioral"])
	}
}

// startLogReader listens on the log channel and updates the GUI
func (s *SecuritySuiteInterface) startLogReader() {
	go func() {
		for msg := range s.logChannel {
			s.logHistory = append(s.logHistory, msg)

			timestamp := time.Now().Format("15:04:05")
			level := msg.Level
			text := msg.Text

			var style widget.RichTextStyle
			switch level {
			case "ALERT":
				style.ColorName = theme.ColorNameError
				style.TextStyle.Bold = true
			case "ERROR":
				style.ColorName = theme.ColorNameWarning
			default:
				style.ColorName = theme.ColorNameForeground
			}

			s.logWidget.Segments = append(s.logWidget.Segments,
				&widget.TextSegment{
					Text:  fmt.Sprintf("[%s] [%s] %s\n", timestamp, level, text),
					Style: style,
				},
			)

			s.window.Canvas().Refresh(s.logWidget)

			if level == "ALERT" {
				dialog.ShowConfirm("SECURITY ALERT", "Critical Alert Received:\n"+text, func(confirmed bool) {
					// Handle user response if needed
				}, s.window)
			}
		}
	}()
}

// Run starts the Fyne GUI application
func (s *SecuritySuiteInterface) Run() {
	s.window.SetMaster()
	s.window.ShowAndRun()
}
