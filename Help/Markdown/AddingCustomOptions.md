# Adding Custom Options

## Options Dialog

Bring up the options dialog in Qt Designer using the `designer` command and then open the _FISSURE/UI/options.ui_ file. Click the arrows for the stacked widget (top right) to locate the table where the custom option will be inserted. Double-click on the table and add a new row with the name of the variable. Set the font size to match the other rows with the "Properties<<" button.

## default.yaml

Open _FISSURE/YAML/User Configs/default.yaml_ and insert the variable name and value (fft_size: 4096) for the new option.

## dashboard.py

Access the variable in _dashboard.py_ with: `int(self.dashboard_settings_dictionary['fft_size'])`.
