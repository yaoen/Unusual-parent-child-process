# Unusual-parent-child-process

## How to set-up
  1. Clone the repo
  ```
  git clone https://github.com/yaoen/Unusual-parent-child-process.git
  ```
  2. Unzip dataset.zip for training datasets
  ```
  unzip dataset.zip -d dataset
  ```
  3. Unzip test_dataset.zip for testing datasets
  ```
  unzip test_dataset.zip -d test_dataset
  ```
  4. Run the training.py script to train the model
  ```
  python training.py <path to training dataset folder> <model output path>
  ```
  5. Run the scoring.py script to score on new dataset
  ```
  python scoring.py <path to new dataset (csv file)> <model path> <output path>
  ```
  6. CSV output contain communities of unusual processes

## Adversary emulation tools
Tools used to generate datasets
 1. https://pentestit.com/adversary-emulation-tools-list/
## Additional tools
 1. https://github.com/infosecn1nja/Red-Teaming-Toolkit
 
 ## Sysmon
 1. Download Sysmon
 ```
 https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
 ```
 2. Install Sysmon with default configurations
 ```
 sysmon -accepteula -i
 sysmon -c --
 ```
 3. Sysmon logs can be viewed at
 ```
 Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> Sysmon
 ```
 4. Sysmon logs can be saved as csv
 5. Sysmon configuration file can be modified to include other events

## Acknowledgements
ProblemChild
1. https://www.elastic.co/blog/discovering-anomalous-patterns-based-on-parent-child-process-relationships
2. https://docs.google.com/presentation/d/1bcdBzxedIDwgAgXJr3LGfIaauk_YnCw3z562N1jYEzE/edit#slide=id.g63334c1b1d_0_446
