package main

import (
	"archive/zip"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"encoding/base64"
	b64 "encoding/base64"
	"path/filepath"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/crypto/curve25519"
)

type MyMainWindow struct {
	*walk.MainWindow
	model               *WGInterfacesModel
	lb                  *walk.ListBox
	peerSection         *walk.ScrollView
	hiddenPeerContainer *walk.Composite
	db                  *walk.DataBinder
}

var boldFont = Font{Family: "MS Shell Dlg 2", PointSize: 8, Bold: true}

func main() {
	mw := &MyMainWindow{model: &WGInterfacesModel{}}

	MainWindow{
		Title:    "Manage WireGuard Tunnels",
		AssignTo: &mw.MainWindow,
		MinSize:  Size{600, 350},
		// Icon:     "icon.ico",
		DataBinder: DataBinder{
			AssignTo:       &mw.db,
			Name:           "tunnel",
			DataSource:     mw.model,
			ErrorPresenter: ToolTipErrorPresenter{},
		},
		Layout: HBox{},
		Children: []Widget{
			Composite{
				Layout: VBox{MarginsZero: true, SpacingZero: true},
				Children: []Widget{
					ListBox{
						AssignTo:              &mw.lb,
						Model:                 mw.model,
						OnCurrentIndexChanged: mw.currentIndexChanged,
					},
					Composite{
						Layout: HBox{MarginsZero: true, SpacingZero: true},
						Children: []Widget{
							ToolBar{
								ButtonStyle: ToolBarButtonTextOnly,
								Items:       mw.leftSectionMenu(),
							},
						},
					},
				},
			},
			Composite{
				StretchFactor: 2,
				Layout:        VBox{MarginsZero: true},
				Children:      mw.rightSection(),
			},
			Composite{
				Visible:  false,
				AssignTo: &mw.hiddenPeerContainer,
			},
		},
		Functions: map[string]func(args ...interface{}) (interface{}, error){
			"addr": func(args ...interface{}) (interface{}, error) {
				return joinAddresses(args[0].([]IPAddressRange)), nil
			},
			"dns": func(args ...interface{}) (interface{}, error) {
				output := ""
				if dnss, ok := args[0].([]DNSServer); ok {
					for i, address := range dnss {
						if i == 0 {
							output += address.String()
						} else {
							output += ", " + address.String()
						}
					}
				}
				return output, nil
			},
			"hasdns": func(args ...interface{}) (interface{}, error) {
				dnss, ok := args[0].([]DNSServer)
				return ok && len(dnss) > 0, nil
			},

			"pubkey": func(args ...interface{}) (interface{}, error) {

				decoded, ok := args[0].([]byte)
				if !ok {
					return "", nil
				}
				if len(decoded) != 32 {
					return "", nil
				}
				var p [32]byte
				var s [32]byte
				copy(s[:], decoded[:32])
				curve25519.ScalarBaseMult(&p, &s)
				return base64.StdEncoding.EncodeToString(p[:]), nil
			},
		},
	}.Run()
}

func (mw *MyMainWindow) leftSectionMenu() []MenuItem {
	return []MenuItem{
		Menu{
			Text: "+",
			Items: []MenuItem{
				Action{
					Text:        "Add empty tunnel",
					OnTriggered: mw.newTunnel,
				},
				Action{
					Text:        "Import tunnel(s) from file...",
					OnTriggered: mw.importTunnels,
				},
			},
		},
		Action{
			Text: "−", //special character. normal "-" doesn't display??
			OnTriggered: func() {
				if cmd, err := RunRequestDialog(mw); err != nil {
					log.Print(err)
				} else if i := mw.lb.CurrentIndex(); cmd == walk.DlgCmdOK && i >= 0 {
					mw.model.items = append(mw.model.items[:i], mw.model.items[i+1:]...)
					mw.model.PublishItemsReset()
				}
			},
		},
		Menu{
			Text: "⚙",
			Items: []MenuItem{
				Action{
					Text: "Export log to file...",
					OnTriggered: func() {
						dlg := new(walk.FileDialog)

						dlg.FilePath = "/"
						dlg.Filter = "Log files (*.log)|*.log"
						dlg.Title = "Save to..."

						if ok, err := dlg.ShowSave(mw); err != nil {
							log.Print(err)
						} else if ok {
							//save log file here
						}
					},
				},
				Action{
					Text: "Export tunnels to zip...",
					OnTriggered: func() {
						dlg := new(walk.FileDialog)

						dlg.FilePath = "/"
						dlg.Filter = "WireGuard tunnel files (*.zip;*.conf)|*.zip;*.conf"
						dlg.Title = "Save to..."

						if ok, err := dlg.ShowSave(mw); err != nil {
							log.Print(err)
						} else if ok {
							//save zipped tunnels
						}
					},
				},
			},
		},
	}
}

func (mw *MyMainWindow) newTunnel() {
	mw.model.items = append(mw.model.items, TunnelConfiguration{Name: "unnamed"})
	mw.model.PublishItemsReset()
}

func (mw *MyMainWindow) importTunnels() {
	dlg := new(walk.FileDialog)

	dlg.Filter = "WireGuard tunnel files (*.zip;*.conf)|*.zip;*.conf"
	dlg.Title = "Import tunnel file..."

	if ok, err := dlg.ShowOpen(mw); err != nil {
		log.Print(err)
	} else if !ok {
		return
	}
	filename := filepath.Base(dlg.FilePath)
	ext := filepath.Ext(filename)
	switch ext {
	case ".conf":
		b, err := ioutil.ReadFile(dlg.FilePath)
		if err != nil {
			walk.MsgBox(
				mw,
				fmt.Sprintf("The file couldn't be accessed:\n%v", err),
				"Error",
				walk.MsgBoxOK|walk.MsgBoxIconError)
			return
		}
		fileWOExt := strings.TrimSuffix(filename, ext)
		tunnel, err := readTunnelConfiguration(string(b), fileWOExt)
		if err != nil {
			walk.MsgBox(
				mw,
				fmt.Sprintf("The file couldn't be read:\n%v", err),
				"Error",
				walk.MsgBoxOK|walk.MsgBoxIconError)
			return
		}
		mw.model.items = append(mw.model.items, tunnel)
	case ".zip":
		z, err := zip.OpenReader(dlg.FilePath)
		if err != nil {
			walk.MsgBox(
				mw,
				fmt.Sprintf("The file couldn't be accessed:\n%v", err),
				"Error",
				walk.MsgBoxOK|walk.MsgBoxIconError)
			return
		}
		defer z.Close()
		for _, f := range z.File {
			innerExt := filepath.Ext(f.Name)
			innerWOExt := strings.TrimSuffix(f.Name, innerExt)
			rc, err := f.Open()
			if err != nil {
				log.Fatal(err)
			}
			b, err := ioutil.ReadAll(rc)
			if err != nil {
				log.Fatal(err)
			}
			rc.Close()

			tunnel, err := readTunnelConfiguration(string(b), innerWOExt)
			if err != nil {
				walk.MsgBox(
					mw,
					fmt.Sprintf("The file couldn't be read:\n%v", err),
					"Error",
					walk.MsgBoxOK|walk.MsgBoxIconError)
				return
			}
			mw.model.items = append(mw.model.items, tunnel)
		}
	default:
		walk.MsgBox(
			mw,
			fmt.Sprintf("Unrecognized file %v", filename),
			"Error",
			walk.MsgBoxOK|walk.MsgBoxIconError)
		return

	}
	mw.model.PublishItemsReset()
}

func (mw *MyMainWindow) rightSection() []Widget {
	return []Widget{
		Composite{
			Layout: Grid{Columns: 2},
			Children: []Widget{
				Label{
					Text:          "Interface:",
					TextAlignment: AlignFar,
					Font:          boldFont,
				},
				LineEdit{
					Text:      Bind("Current.Name"),
					ReadOnly:  true,
					Alignment: AlignNear,
				},
				Label{
					Text:          "Public key:",
					TextAlignment: AlignFar,
				},
				LineEdit{
					Text:     Bind("pubkey(tunnel.Current.WGInterface.PrivateKey)"),
					ReadOnly: true,
				},
				// Label{
				// 	Text:          "Listen port:",
				// 	TextAlignment: AlignFar,
				// },
				// LineEdit{
				// 	Text:     Bind("Current.WGInterface.ListenPort"),
				// 	ReadOnly: true,
				// },

				Label{
					Text:          "Addresses:",
					TextAlignment: AlignFar,
				},
				LineEdit{
					Text:     Bind("addr(tunnel.Current.WGInterface.Addresses)"),
					ReadOnly: true,
				},

				Label{
					Text:          "DNS servers:",
					Visible:       Bind("hasdns(tunnel.Current.WGInterface.DNSServer)"),
					TextAlignment: AlignFar,
				},
				LineEdit{
					Text:     Bind("dns(tunnel.Current.WGInterface.DNSServer)"),
					Visible:  Bind("hasdns(tunnel.Current.WGInterface.DNSServer)"),
					ReadOnly: true,
				},
				VSpacer{
					ColumnSpan: 2,
					Size:       5,
				},

				ScrollView{
					AssignTo:   &mw.peerSection,
					Layout:     VBox{MarginsZero: true, Spacing: 15},
					ColumnSpan: 2,
				},

				VSpacer{
					ColumnSpan: 2,
					Size:       5,
				},
				Label{
					Text:          "On-Demand:",
					TextAlignment: AlignFar,
				},
				LineEdit{
					Text:     "Off",
					ReadOnly: true,
				},
				VSpacer{
					ColumnSpan: 2,
				},
			},
		},
		Composite{
			Layout: HBox{},
			Children: []Widget{

				Label{
					Text: "Status: deactivated",
				},
				CheckBox{
					Checked: false,
				},
				HSpacer{},
				PushButton{
					Text: "Edit",
					OnClicked: func() {
						updateDetails(mw)
						//outTE.SetText(strings.ToUpper(inTE.Text()))
					},
				},
			},
		},
	}
}

func joinAddresses(adds []IPAddressRange) string {
	output := ""
	for i, address := range adds {
		if i == 0 {
			output += address.String()
		} else {
			output += ", " + address.String()
		}
	}
	return output
}

func updateDetails(mw *MyMainWindow) {
}

func (mw *MyMainWindow) currentIndexChanged() {

	i := mw.lb.CurrentIndex()
	var current TunnelConfiguration
	if i < 0 || i >= len(mw.model.items) {
		current = TunnelConfiguration{}
	} else {
		current = mw.model.items[i]
	}

	mw.model.Current = current
	mw.db.Reset()
	for _, p := range mw.model.Current.Peers {
		getPeer(p).Create(NewBuilder(mw.peerSection))
	}
}

var peercount = 0

func getPeer(p PeerConfiguration) Composite {

	return Composite{
		Layout: Grid{Columns: 2, MarginsZero: true},
		Children: []Widget{
			Label{
				Text:          "Peer:",
				TextAlignment: AlignFar,
				Font:          boldFont,
			},
			LineEdit{
				Text:     b64.StdEncoding.EncodeToString(p.PublicKey),
				ReadOnly: true,
			},
			Label{
				Text:          "Endpoint:",
				TextAlignment: AlignFar,
			},
			LineEdit{
				Text:     p.Endpoint.String(),
				ReadOnly: true,
			},

			Label{
				Text:          "Allowed IPs:",
				TextAlignment: AlignFar,
			},
			LineEdit{
				Text:     joinAddresses(p.AllowedIPs),
				ReadOnly: true,
			},
			// VSpacer{
			// 	ColumnSpan: 2,
			// 	Size:       5,
			// },
		},
	}
}

func RunRequestDialog(owner walk.Form) (int, error) {
	var dlg *walk.Dialog
	return Dialog{
		AssignTo: &dlg,
		// Icon:     "icon.ico",
		Title:  "Confirm",
		Layout: VBox{},
		Children: []Widget{
			Label{
				Text: "Are you sure?",
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						Text: "Yes",
						OnClicked: func() {
							dlg.Accept()
						},
					},
					PushButton{
						Text:      "No",
						OnClicked: func() { dlg.Cancel() },
					},
				},
			},
		},
	}.Run(owner)
}

func RunEditDialog(owner walk.Form) (int, error) {
	var dlg *walk.Dialog
	return Dialog{
		AssignTo: &dlg,
		// Icon:     "icon.ico",
		Title:  "Edit Interface",
		Layout: Grid{Columns: 2},
		Children: []Widget{
			Label{
				Text: "Name:",
			},
			LineEdit{
				Text: "krantz",
			},
			Label{
				Text:          "Public key:",
				TextAlignment: AlignFar,
			},
			LineEdit{
				Text:     "RhBoY...",
				ReadOnly: true,
			},
			Composite{
				ColumnSpan: 2,
				Layout:     HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						Text: "Yes",
						OnClicked: func() {
							dlg.Accept()
						},
					},
					PushButton{
						Text:      "No",
						OnClicked: func() { dlg.Cancel() },
					},
				},
			},
		},
	}.Run(owner)
}

type WGInterfacesModel struct {
	walk.ListModelBase
	items   []TunnelConfiguration
	Current TunnelConfiguration
}

func (m *WGInterfacesModel) ItemCount() int {
	return len(m.items)
}

func (m *WGInterfacesModel) Value(index int) interface{} {
	return m.items[index].Name
}
