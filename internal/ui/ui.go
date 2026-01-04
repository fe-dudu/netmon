package ui

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/google/gopacket/pcap"
	"github.com/rivo/tview"

	"github.com/fe-dudu/netmon/internal/network"
	"github.com/fe-dudu/netmon/internal/packet"
	"github.com/fe-dudu/netmon/internal/types"
	"github.com/fe-dudu/netmon/internal/utils"
)

func NewApp(ifaces []pcap.Interface, handles []*pcap.Handle, filterIdx int) *types.App {
	app := &types.App{
		App:              tview.NewApplication(),
		Packets:          make([]types.PacketInfo, 0),
		CurrentFilterIdx: filterIdx,
		IsExpandedMode:   false,
		Ifaces:           ifaces,
		Handles:          handles,
		PacketCh:         make(chan types.PacketInfo, 1000),
		StopCh:           make(chan struct{}),
	}

	app.PacketView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextColor(tcell.ColorWhite).
		SetScrollable(true).
		SetWrap(false).
		SetChangedFunc(func() {
			app.App.Draw()
		})
	app.PacketView.SetBorder(true).
		SetBorderColor(tcell.ColorBlue).
		SetTitle("[blue]📦 Packets[white]").
		SetTitleAlign(tview.AlignLeft)

	app.FilterView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	app.FilterView.SetBorder(true).
		SetBorderColor(tcell.ColorYellow).
		SetTitle("[yellow]🔧 Filters[white]").
		SetTitleAlign(tview.AlignLeft)

	app.ModeView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	app.ModeView.SetBorder(true).
		SetBorderColor(tcell.ColorGreen).
		SetTitle("[green]📐 Mode[white]").
		SetTitleAlign(tview.AlignLeft)

	app.SearchInput = tview.NewInputField().
		SetPlaceholder("Press Enter↵ to search").
		SetPlaceholderStyle(tcell.StyleDefault.Foreground(tcell.ColorWhite).Background(tcell.ColorBlack)).
		SetFieldBackgroundColor(tcell.ColorBlack).
		SetChangedFunc(func(text string) {
			app.SearchIP = strings.TrimSpace(text)
			UpdateDisplay(app)
		}).
		SetDoneFunc(func(key tcell.Key) {
			if key == tcell.KeyEscape {
				app.IsSearchMode = false
				app.SearchInput.SetText("")
				app.SearchIP = ""
				app.App.SetFocus(app.PacketView)
				UpdateFilterView(app)
				UpdateDisplay(app)
			}
		})
	app.SearchInput.SetBorder(true).
		SetBorderColor(tcell.ColorRed).
		SetTitle("[red]🔍 Search[white]").
		SetTitleAlign(tview.AlignLeft).
		SetBackgroundColor(tcell.ColorBlack)

	app.MainFlex = tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(
			tview.NewFlex().
				SetDirection(tview.FlexRow).
				AddItem(app.FilterView, 0, 1, false).
				AddItem(app.ModeView, 3, 0, false),
			14, 0, false).
		AddItem(
			tview.NewFlex().
				SetDirection(tview.FlexRow).
				AddItem(app.PacketView, 0, 1, true).
				AddItem(app.SearchInput, 3, 0, false),
			0, 1, true)

	UpdateFilterView(app)
	UpdateModeView(app)
	SetupKeyBindings(app)

	return app
}

func SetupKeyBindings(a *types.App) {
	a.App.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if a.IsSearchMode {
			if event.Key() == tcell.KeyEscape {
				a.IsSearchMode = false
				a.SearchInput.SetText("")
				a.SearchIP = ""
				a.App.SetFocus(a.PacketView)
				UpdateFilterView(a)
				UpdateDisplay(a)
				return nil
			}
			if event.Key() == tcell.KeyRune {
				r := event.Rune()
				isValid := (r >= '0' && r <= '9') ||
					r == '.' ||
					r == ':' ||
					(r >= 'a' && r <= 'f') ||
					(r >= 'A' && r <= 'F')
				if !isValid {
					return nil
				}
			}
			return event
		}

		switch event.Key() {
		case tcell.KeyEscape, tcell.KeyCtrlC:
			Stop(a)
			return nil
		case tcell.KeyEnter:
			a.IsSearchMode = true
			a.App.SetFocus(a.SearchInput)
			UpdateFilterView(a)
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case '1', '2', '3', '4', '5', '6', '7', '8':
				idx := int(event.Rune() - '1')
				if idx < len(types.ProtocolFilters) {
					ChangeFilter(a, idx)
				}
				return nil
			case 'm', 'M':
				a.IsExpandedMode = !a.IsExpandedMode
				UpdateModeView(a)
				UpdateDisplay(a)
				return nil
			}
		}
		return event
	})
}

func ChangeFilter(a *types.App, idx int) {
	if idx == a.CurrentFilterIdx {
		return
	}

	a.CurrentFilterIdx = idx
	filter := types.ProtocolFilters[idx]

	for i, handle := range a.Handles {
		if handle == nil {
			continue
		}
		if err := handle.SetBPFFilter(filter.BPF); err != nil {
			log.Printf("Failed to change filter on %s: %v", a.Ifaces[i].Name, err)
		}
	}

	UpdateFilterView(a)
	UpdateDisplay(a)
}

func UpdateFilterView(a *types.App) {
	var builder strings.Builder

	for i, filter := range types.ProtocolFilters {
		num := i + 1
		text := fmt.Sprintf("[%d] %s", num, filter.Label)

		if i == a.CurrentFilterIdx {
			fmt.Fprintf(&builder, "[black:yellow:bi]%-12s[black:white]", text)
		} else {
			fmt.Fprintf(&builder, "[white:black]%-12s[white]", text)
		}
	}

	if a.IsSearchMode {
		a.SearchInput.SetTitle("[red]🔍 Search [red](ESC to close)[white]")
	} else {
		a.SearchInput.SetTitle("[red]🔍 Search[white]")
	}

	a.FilterView.SetText(builder.String())
}

func UpdateModeView(a *types.App) {
	var builder strings.Builder

	if a.IsExpandedMode {
		fmt.Fprintf(&builder, "[white:black]%-12s[white]", "Expanded")
	} else {
		fmt.Fprintf(&builder, "[white:black]%-12s[white]", "Compact")
	}

	a.ModeView.SetText(builder.String())
}

func UpdateDisplay(a *types.App) {
	a.PacketsMutex.RLock()
	defer a.PacketsMutex.RUnlock()

	var builder strings.Builder
	count := 0
	maxDisplay := 10000

	if len(a.Packets) == 0 {
		fmt.Fprintf(&builder, "[white]Waiting for packets...[white]\n")
		fmt.Fprintf(&builder, "[white]Network traffic will be displayed here when detected.[white]\n")
	}

	for i := len(a.Packets) - 1; i >= 0 && count < maxDisplay; i-- {
		pkt := a.Packets[i]

		if !packet.MatchesFilter(a.CurrentFilterIdx, pkt) {
			continue
		}

		if a.SearchIP != "" {
			searchLower := strings.ToLower(a.SearchIP)
			srcLower := strings.ToLower(pkt.Src)
			dstLower := strings.ToLower(pkt.Dst)
			if !strings.Contains(srcLower, searchLower) && !strings.Contains(dstLower, searchLower) {
				continue
			}
		}

		protoColor := GetProtoColor(pkt.Proto)

		safeSrc := utils.SanitizeForDisplay(pkt.Src)
		safeDst := utils.SanitizeForDisplay(pkt.Dst)
		safeDetail := utils.SanitizeForDisplay(pkt.Detail)

		detailStr := ""
		if safeDetail != "" {
			detailStr = fmt.Sprintf(" [yellow]%s[white]", safeDetail)
		}

		var srcDisplay, dstDisplay string
		var srcWidth, dstWidth int
		var timeFormat string

		if a.IsExpandedMode {
			srcDisplay = HighlightSearch(safeSrc, a.SearchIP, "cyan")
			dstDisplay = HighlightSearch(safeDst, a.SearchIP, "magenta")
			srcWidth = 50
			dstWidth = 50
			timeFormat = "15:04:05.000"
		} else {
			srcDisplay = HighlightSearch(utils.TruncateString(safeSrc, 35), a.SearchIP, "cyan")
			dstDisplay = HighlightSearch(utils.TruncateString(safeDst, 35), a.SearchIP, "magenta")
			srcWidth = 35
			dstWidth = 35
			timeFormat = "15:04:05"
		}

		srcPadded := utils.PadString(srcDisplay, srcWidth)
		dstPadded := utils.PadString(dstDisplay, dstWidth)
		fmt.Fprintf(&builder, "[%s:black:bi] %-6s [white] [gray]│[white] %s [gray]→[white] %s [gray]│[white] [gray]%s[white]%s\n",
			protoColor, pkt.Proto, srcPadded, dstPadded, pkt.Timestamp.Format(timeFormat), detailStr)
		count++
	}

	a.PacketView.SetText(builder.String())
}

func HighlightSearch(text, search, defaultColor string) string {
	if search == "" {
		return fmt.Sprintf("[%s]%s[white]", defaultColor, text)
	}

	searchLower := strings.ToLower(search)
	textLower := strings.ToLower(text)

	if !strings.Contains(textLower, searchLower) {
		return fmt.Sprintf("[%s]%s[white]", defaultColor, text)
	}

	var result strings.Builder
	idx := strings.Index(textLower, searchLower)
	if idx > 0 {
		result.WriteString(fmt.Sprintf("[%s]%s[white]", defaultColor, text[:idx]))
	}
	result.WriteString(fmt.Sprintf("[yellow:black:bi]%s[white]", text[idx:idx+len(search)]))
	if idx+len(search) < len(text) {
		result.WriteString(fmt.Sprintf("[%s]%s[white]", defaultColor, text[idx+len(search):]))
	}

	return result.String()
}

func GetProtoColor(proto string) string {
	switch proto {
	case "DNS":
		return "green"
	case "HTTP":
		return "blue"
	case "TLS":
		return "yellow"
	case "HTTPS":
		return "orange"
	case "TCP":
		return "cyan"
	case "UDP":
		return "magenta"
	case "QUIC":
		return "purple"
	case "ICMP", "ICMPv6":
		return "red"
	default:
		return "white"
	}
}

func Run(a *types.App) {
	network.StartPacketCapture(a)

	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-a.StopCh:
				return
			case <-ticker.C:
				UpdateDisplay(a)
			}
		}
	}()

	a.App.EnableMouse(true)

	if err := a.App.SetRoot(a.MainFlex, true).SetFocus(a.PacketView).Run(); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}

func Stop(a *types.App) {
	close(a.StopCh)
	a.App.Stop()
}
