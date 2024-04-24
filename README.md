# T3 - G14

## Authors
Jozef Porubcin, Hannah Sanchez, Patrick Pendergast

## Notes
Do **NOT** execute any of the executable files. Remove execute permissions from all of the executable files as soon as you download them. Accidentally double-clicking on just one of the files is all it can take to run live malware on your machine.

## How to Run

### Setup
1. `pip install -r requirements.txt`
1. `conda install --channel conda-forge --file requirements.yaml`

There are two datasets: the sample and the raw one.

### Sample Dataset
1. Open `T3.ipynb`.
1. Enter the necessary paths in cell 2.
1. Run cells 1-14 to generate the necessary data and label CSV files. Once generated, cells 1-14 don't need to be re-run.
1. Run all of the cells after cell 15.

### Raw Dataset
1. Open `Raw_Data_Handler.ipynb`.
1. Enter the necessary paths in cell 2.
1. Run all of the cells.
1. Close `Raw_Data_Handler.ipynb`.
1. Open `T3.ipynb`.
1. Enter the necessary paths in cell 2.
1. Run cells 1-14 to generate the necessary data and label CSV files. Once generated, cells 1-14 don't need to be re-run.
1. Run all of the cells after cell 15.