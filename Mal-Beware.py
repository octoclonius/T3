import magic
import PySimpleGUI as sg

def scan_file(filename):
    # Grab file object, give to AI, return either malware or not
    output = filename

    # Use magic number to determine file type
    filetype = magic.from_file(filename)
    output += "\nFile is of type " + filetype

    return output

layout = [[sg.Text('What file do you want to scan?')], 
          [sg.Input(key='-IN-', enable_events=True), sg.FileBrowse(target='-IN-', initial_folder='Downloads')],
          [sg.Text(key='-OUT-', size=(50,10), text='')],
          [sg.Button('Exit')]]
window = sg.Window('File Scan', layout)

while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Exit':
        break
    if event == '-IN-':
        filename = values[event]
        output = scan_file(filename)
        window['-OUT-'].update(output)

window.close()