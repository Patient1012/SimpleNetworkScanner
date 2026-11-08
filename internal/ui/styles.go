package ui

import (
	"github.com/charmbracelet/lipgloss"
)

type styles struct {
	accent       lipgloss.Style
	title        lipgloss.Style
	text         lipgloss.Style
	muted        lipgloss.Style
	green        lipgloss.Style
	yellow       lipgloss.Style
	red          lipgloss.Style
	cyan         lipgloss.Style
	header       lipgloss.Style
	headerActive lipgloss.Style
	selBar       lipgloss.Style
	box          lipgloss.Style
	boxTitle     lipgloss.Style
	key          lipgloss.Style
	selectedBG   lipgloss.AdaptiveColor
}

func newStyles() styles {
	accent := lipgloss.AdaptiveColor{Light: "#0969DA", Dark: "#5FD7FF"}
	green := lipgloss.AdaptiveColor{Light: "#1A7F37", Dark: "#5FD787"}
	yellow := lipgloss.AdaptiveColor{Light: "#9A6700", Dark: "#FFD75F"}
	red := lipgloss.AdaptiveColor{Light: "#CF222E", Dark: "#FF6B6B"}
	muted := lipgloss.AdaptiveColor{Light: "#6E7781", Dark: "#7D8590"}
	text := lipgloss.AdaptiveColor{Light: "#1F2328", Dark: "#E6EDF3"}
	border := lipgloss.AdaptiveColor{Light: "#AFB8C1", Dark: "#3D444D"}
	selBG := lipgloss.AdaptiveColor{Light: "#DDF4FF", Dark: "#17262E"}

	return styles{
		accent:       lipgloss.NewStyle().Foreground(accent),
		title:        lipgloss.NewStyle().Bold(true).Foreground(accent),
		text:         lipgloss.NewStyle().Foreground(text),
		muted:        lipgloss.NewStyle().Foreground(muted),
		green:        lipgloss.NewStyle().Foreground(green),
		yellow:       lipgloss.NewStyle().Foreground(yellow),
		red:          lipgloss.NewStyle().Foreground(red),
		cyan:         lipgloss.NewStyle().Foreground(accent),
		header:       lipgloss.NewStyle().Bold(true).Foreground(muted),
		headerActive: lipgloss.NewStyle().Bold(true).Foreground(accent),
		selBar:       lipgloss.NewStyle().Bold(true).Foreground(accent).Background(selBG),
		box: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(border).
			Padding(1, 2),
		boxTitle:   lipgloss.NewStyle().Bold(true).Foreground(accent),
		key:        lipgloss.NewStyle().Bold(true).Foreground(accent),
		selectedBG: selBG,
	}
}
