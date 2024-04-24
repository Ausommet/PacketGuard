# PacketGuard
#THIS NEEDS UPDATE!!!
Unlock insights from .pcap files. Packetguard a tool to process these files, generating .csv data for user-defined classification or utilizing built-in classifiers trained on the UNSW-NB15 dataset. Results are conveniently presentted in a readable .csv format for seamless analysis

## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Data Generation](#data-generation)
6. [Packet Generation](#packet-generation)
7. [Models](#models)
8. [Results](#results)
9. [Contributing](#contributing)
10. [License](#license)

## Introduction

PacketGuard - a Python-powered solution for .pcap file analysis, offering an alternative to traditional methods like Wireshark. Designed to expedite the analysis of vast amounts of network traffic data, PacketGuard simplifies the process and also generates structured data from .pcap files for integration with classifiers and datasets. Reducing time-consuming analysis with Wireshark with effiient insights with PacketGuard.

## Features

1. **Efficient .pcap Analysis**: PacketGuard uses rdpcap for reading the of .pcap files, offering a faster and more efficient alternative to tools like Wireshark. However in the future there is plan to use a Generator as an even faster alternative to rdpcap.

2. **Data Generation**: Automatically generates structured data from .pcap files, enabling seamless integration with classifiers or datasets for further analysis.

3. **Classifier Integration**: Built-in classifiers trained on datasets like UNSW-NB15 facilitate quick and accurate classification of network traffic data.

4. **Custom Classification**: Allows users to define their own classification tasks using the generated data, providing flexibility for specific analysis requirements.

5. **Readable Output**: Presents classified data in a readable .csv format, making it easy for users to interpret and further analyze the results.

6. **Python-Based**: Written in Python, PacketGuard offers a familiar environment for users comfortable with the language, along with the flexibility to customize and extend its functionality.

7. **User-Friendly Interface**: Features an intuitive CLI interface that simplifies the process of analyzing and interpreting network traffic data, suitable for both novice and experienced users.

8. **Scalability**: Capable of handling large volumes of .pcap files efficiently, ensuring consistent performance even with extensive datasets.

9. **Documentation and Support**: Comprehensive documentation and support resources are provided to assist users in getting started with the tool and troubleshooting any issues.

10. **Open Source**: PacketGuard is open-source, allowing for community contributions, customization, and ongoing development to meet evolving needs and requirements.

These features highlight the functionality and benefits of PacketGuard, demonstrating its value proposition to users interested in analyzing .pcap files efficiently.

## Installation

To get started with PacketGuard, simply follow these steps:
1. Clone the repository to your local machine:
```
git clone  TDB
```
2. Navigate to the project directory:
```
cd TBD
```
3. Install the required dependencies using pip:
```
pip install -r requirements.txt (To Be Added at a later date)
```
Once the dependencies are installed, you're ready to use PacketGuard for analyzing .pcap files efficiently!

Ensure you have Python and pip installed on your system before proceeding with the installation. 

## Usage

To utilize the Packet Classifier Application, follow these steps:

1. Ensure you have Python installed on your system.
2. Clone the repository or download the application files to your local machine.
3. Navigate to the directory containing the application files.
4. Run the application using the following command:
```
python <filename>.py -f <path_to_pcap_file> -m <model_choice> -t <training_data>
```
Replace <filename>.py with the name of your Python script.

Replace <path_to_pcap_file> with the path to the .pcap file you want to analyze.

Replace <model_choice> with either "DTC" for Decision Tree Classifier or "RFC" for Random Forest Classifier.

5. Follow the prompts displayed in the terminal:
Choose whether to save the generated results (y/n).

If applicable, choose whether to save the prediction results (y/n).

6. Wait for the application to process the data, train the selected model, and perform prediction.
7. Once completed, the application will display the time taken for prediction and any saved results will be available in the specified location.

8. You can now analyze the prediction results and further investigate the network traffic data as needed.

If you encounter any issues or have questions, refer to the documentation or reach out to our support team for assistance.

## Data Generation

The data generation process in PacketGuard involves analyzing .pcap files and extracting relevant information from each packet. Here's an overview of the steps involved:

1. Packet Reading: Packet data is read from the .pcap file using the rdpcap function from the scapy library.

2. Packet Information Extraction: Information is extracted from each packet, including duration, protocol, service, state, packet counts, bytes, rates, TTL (Time to Live), load, packet loss, packet size means, transmission depth, response body length, TCP sequence numbers, and various connection tracking parameters.

3. Derived Metrics Calculation: Derived metrics such as inter-arrival times, TCP RTT (Round-Trip Time), SYN-ACK and ACK-DAT delays, mean packet sizes, connection tracking metrics, FTP-related metrics, HTTP flow methods, and others are calculated based on the extracted packet information.

4. Data Structure Initialization: Data structures and variables are initialized to store running averages, total packet sizes, packet counts, connection timestamps, and other relevant information.

5. Data Storage: If specified by the user, the generated packet data is stored in a .csv file for further analysis and processing.

6. Iterative Processing: The packet processing and information extraction are performed iteratively over all packets in the .pcap file, ensuring comprehensive coverage and accurate data representation.

Overall, this process ensures that essential packet information is captured and organized effectively, enabling users to analyze network traffic data efficiently and derive meaningful insights for classification and analysis tasks.

## Models

### Decision Tree Classifier (DTC)

The Decision Tree Classifier (DTC) is a machine learning algorithm used for classification tasks. In the project, the DTC model is trained to classify network packet data into different attack categories. Here's a description of the DTC model used in the project:

1. **Data Preprocessing**:
   - The dataset, presumably containing features extracted from network packets, is loaded from a CSV file.
   - Rows with specified values, such as "-", are removed from certain columns to clean the data.
   - Rows with "Generic" values in the "service" column are removed.
   - The "attack_cat" column is label encoded using `LabelEncoder()` to convert categorical labels into numerical format.
   - Categorical variables are one-hot encoded to prepare the data for model training.

2. **Model Training**:
   - The dataset is split into features (X) and the target variable (y).
   - The dataset is further split into training and testing sets using `train_test_split()` from `sklearn.model_selection`.
   - A Decision Tree classifier is initialized with default parameters.
   - The model is trained on the training data using `fit()`.
   - The trained model is saved to a pickle file along with the label encoder.

3. **Model Evaluation**:
   - The trained model is used to make predictions on the testing set.
   - Classification report and accuracy score are printed to evaluate the model's performance.
   
4. **Time Measurement**:
   - The time taken to train the model is measured and printed.

### Random Forest Classifier (RFC)

The Random Forest Classifier (RFC) is an ensemble learning method that constructs a multitude of decision trees during training and outputs the class that is the mode of the classes of the individual trees. Here's a description of the RFC model used in your project:

1. **Data Preprocessing**:
   - Similar data preprocessing steps are performed as in the DTC model.

2. **Model Training**:
   - The dataset is split into features (X) and the target variable (y).
   - The dataset is further split into training and testing sets.
   - A Random Forest classifier is initialized with 100 decision trees (`n_estimators=100`).
   - The model is trained on the training data.
   - The trained model is saved to a pickle file along with the label encoder.

3. **Model Evaluation**:
   - The trained model is used to make predictions on the testing set.
   - Classification report and accuracy score are printed to evaluate the model's performance.

4. **Time Measurement**:
   - The time taken to train the model is measured and printed.

These models provide a way to classify network packet data into different attack categories, allowing for the detection and analysis of network security threats.

## Results (TBD)

Present the results obtained from using the models.

## Contributing (TBD)

Guidelines for contributing to the project.

## License (TBD)

Information about the project's license.
