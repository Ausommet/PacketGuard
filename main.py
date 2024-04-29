import argparse
from tmdtc import train_decision_tree_classifier
from tmrfc import train_random_forest_classifier
from PM import predict
from DG import generate_packet_data
import time
import os.path

def main():
    parser = argparse.ArgumentParser(description="Packet Classifier Application")
    parser.add_argument("-f", help="Path to the .pcap file")
    parser.add_argument("-m", choices=["DTC", "RFC"], help="Choose the training model: DTC (Decision Tree Classifier) or RFC (Random Forest Classifier)")
    parser.add_argument("-t", help="Choose the training model in .csv file format, you can provide your own or use the provided dataset.")

    args = parser.parse_args()
    file_path = args.f
    model_choice = args.m
    training_data = args.t

    # Check if the file path is provided and has a .pcap extension
    if file_path:
        file_base, file_ext = os.path.splitext(file_path)
        if file_ext != ".pcap":
            print("Error: The specified file is not a .pcap file.")
            return

    # Check if the training data file is provided and has a .csv extension
    if training_data:
        training_base, training_ext = os.path.splitext(training_data)
        if training_ext != ".csv":
            print("Error: The specified training data file is not a .csv file.")
            return

    # Check if the file exists
    if file_path and not os.path.exists(file_path):
        print("Error: The specified path to the .pcap file does not exist.")
        return
    # Check if the training data file exists
    if training_data and not os.path.exists(training_data):
        print("Error: The specified training data file does not exist.")
        return

    # Generate packet data from the .pcap file
    save_file = input("Would you like to save the Generated results? (y/n): ").lower()
    if save_file == "y" or save_file =="n":

        packet_data = generate_packet_data(file_path, save_file)
        print("Packet data generated!")

    else:
        print("Invalid input. Please enter 'y' or 'n'.")

    if model_choice == "DTC":
        print("Now training the Decision Tree Classifier...")
        train_decision_tree_classifier(training_data)
    elif model_choice == "RFC":
        print("Now training the Random Forest Classifier...")
        train_random_forest_classifier(training_data)
    else:
        print("Invalid model choice. Please choose between DTC and RFC.")
        return

    # After training, perform prediction
    if model_choice == "DTC":
        savefile = input("Would you like to save the prediction results? (y/n): ").lower()
        if savefile == "y" or savefile == "n":
            start_time = time.time()
            predict("Models/trained_model_DTC.pkl", "Models/label_encoder_DTC.pkl", packet_data, savefile)
        else:
            print("Invalid input. Please enter 'y' or 'n.")
        print("Prediction in progress...")
        print("Prediction completed!")
    elif model_choice == "RFC":
        savefile = input("Would you like to save the prediction results? (y/n): ").lower()
        if savefile == "y" or savefile == "n":
            start_time = time.time()
            predict("Models/trained_model_RFC.pkl", "Models/label_encoder_RFC.pkl", packet_data, savefile)
        else:
            print("Invalid input. Please enter 'y' or 'n.")
        print("Prediction in progress...")
        print("Prediction completed!")
    end_time = time.time()   
    print("Time taken to Predict: {:.2f} seconds".format(end_time - start_time))

if __name__ == "__main__":
    main()
