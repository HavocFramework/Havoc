package colors

import "github.com/fatih/color"

var (
	Blue   = color.New(color.FgBlue).SprintFunc()
	Red    = color.New(color.FgRed).SprintFunc()
	Green  = color.New(color.FgGreen).SprintFunc()
	Yellow = color.New(color.FgYellow).SprintFunc()
	White  = color.New(color.FgHiWhite).SprintFunc()

	BoldBlue   = color.New(color.FgBlue, color.Bold).SprintFunc()
	BoldRed    = color.New(color.FgRed, color.Bold).SprintFunc()
	BoldGreen  = color.New(color.FgGreen, color.Bold).SprintFunc()
	BoldYellow = color.New(color.FgYellow, color.Bold).SprintFunc()
	BoldWhite  = color.New(color.FgHiWhite, color.Bold).SprintFunc()

	RedUnderline    = color.New(color.FgRed).Add(color.Underline).SprintFunc()
	BlueUnderline   = color.New(color.FgBlue).Add(color.Underline).SprintFunc()
	GreenUnderline  = color.New(color.FgGreen).Add(color.Underline).SprintFunc()
	YellowUnderline = color.New(color.FgYellow).Add(color.Underline).SprintFunc()
	WhiteUnderline  = color.New(color.FgHiWhite).Add(color.Underline).SprintFunc()
)
