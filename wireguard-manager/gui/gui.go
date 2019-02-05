package main

import (
	"log"
	"math/rand"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

type MyMainWindow struct {
	*walk.MainWindow
	model *GWInterfacesModel
	lb    *walk.ListBox
	te    *walk.TextEdit
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func main() {

	mw := &MyMainWindow{model: NewInterfacesModel()}
	//var mw *walk.MainWindow

	MainWindow{
		Title:    "Manage WireGuard Tunnels",
		AssignTo: &mw.MainWindow,
		MinSize:  Size{600, 350},
		// Icon:     "icon.ico",
		Layout: HBox{},
		Children: []Widget{
			Composite{
				Layout: VBox{MarginsZero: true, SpacingZero: true},
				Children: []Widget{
					ListBox{
						AssignTo: &mw.lb,
						// Model:    mw.model,
						// OnCurrentIndexChanged: mw.lb_CurrentIndexChanged,
						// OnItemActivated:       mw.lb_ItemActivated,
					},
					Composite{

						Layout: HBox{MarginsZero: true, SpacingZero: true},
						Children: []Widget{
							ToolBar{
								ButtonStyle: ToolBarButtonTextOnly,
								Items: []MenuItem{
									Menu{
										Text: "+",
										Items: []MenuItem{
											Action{
												Text: "Add empty tunnel",
												// OnTriggered: mw.newAction_Triggered,
											},
											Action{
												Text: "Import tunnel(s) from file...",
												OnTriggered: func() {
													dlg := new(walk.FileDialog)

													dlg.FilePath = "/"
													dlg.Filter = "WireGuard tunnel files (*.zip;*.conf)|*.zip;*.conf"
													dlg.Title = "Import tunnel file..."

													if ok, err := dlg.ShowOpen(mw); err != nil {
														log.Print(err)
													} else if ok {
														//load file here
													}
												},
											},
										},
									},
									Action{
										Text: "−", //special character. normal "-" doesn't display??
										OnTriggered: func() {
											if cmd, err := RunRequestDialog(mw); err != nil {
												log.Print(err)
											} else if cmd == walk.DlgCmdOK {
												//delete selected here
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
								},
							},
						},
					},
				},
			},
			Composite{
				StretchFactor: 2,
				Layout:        VBox{},
				Children: []Widget{
					Composite{
						Layout: Grid{Columns: 2},
						Children: []Widget{
							Label{
								Text:          "Interface:",
								TextAlignment: AlignFar,
							},
							LineEdit{
								Text:      "krantz",
								ReadOnly:  true,
								Alignment: AlignNear,
							},
							Label{
								Text:          "Public key:",
								TextAlignment: AlignFar,
							},
							LineEdit{
								Text:     "RhBoY...",
								ReadOnly: true,
							},

							Label{
								Text:          "Addresses:",
								TextAlignment: AlignFar,
							},
							LineEdit{
								Text:     "10.47.28.44/32",
								ReadOnly: true,
							},

							Label{
								Text:          "DNS servers:",
								TextAlignment: AlignFar,
							},
							LineEdit{
								Text:     "1.1.1.1",
								ReadOnly: true,
							},
							VSpacer{
								ColumnSpan: 2,
								Size:       10,
							},

							Label{
								Text:          "Peer:",
								TextAlignment: AlignFar,
							},
							LineEdit{
								Text:     "aveoTuZkNv...",
								ReadOnly: true,
							},
							Label{
								Text:          "Endpoint:",
								TextAlignment: AlignFar,
							},
							LineEdit{
								Text:     "demo.wireguard.com:443",
								ReadOnly: true,
							},

							Label{
								Text:          "Allowed IPs:",
								TextAlignment: AlignFar,
							},
							LineEdit{
								Text:     "0.0.0.0/0, ::/0",
								ReadOnly: true,
							},

							VSpacer{
								ColumnSpan: 2,
								Size:       10,
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
									//outTE.SetText(strings.ToUpper(inTE.Text()))
								},
							},
						},
					},
				},
			},
		},
	}.Run()
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

type GWInterface struct {
	name  string
	value string
}

type GWInterfacesModel struct {
	walk.ListModelBase
	items []GWInterface
}

func NewInterfacesModel() *GWInterfacesModel {
	m := &GWInterfacesModel{items: make([]GWInterface, 5)}

	for i := range m.items {
		m.items[i] = GWInterface{RandStringRunes(7), RandStringRunes(9)}
	}

	return m
}
