# Load necessary libraries
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import joblib
import pickle
import time
import os

def train_random_forest_classifier(file_path):
    
    # Start timing
    start_time = time.time()

    # Load the UNSW_NB15 dataset
    data = pd.read_csv(file_path)

    # Preprocessing steps to remove rows with specified values
    columns_to_check = ["proto", "service", "state", "spkts", "dpkts",
                        "sbytes", "dbytes", "swin", "dwin", "stcpb", "dtcpb"]

    # Remove rows where any of the specified columns have value "-"
    for column in columns_to_check:
        data = data[data[column] != "-"]

    # If 'Generic' values are found, remove rows with 'Generic' values in the 'service' column
    data = data[data['service'] != 'Generic']

    # Label encode the 'attack_cat' column
    label_encoder = LabelEncoder()
    data['attack_cat_encoded'] = label_encoder.fit_transform(data['attack_cat'])

    # One-hot encode categorical variables
    data = pd.get_dummies(data, columns=["proto", "service", "state"])

    # Split the dataset into features and target variable
    X = data.drop(columns=["label", "attack_cat", "attack_cat_encoded"])
    y = data["attack_cat_encoded"]

    # Split the dataset into training and testing sets
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Choose a machine learning algorithm
    from sklearn.ensemble import RandomForestClassifier

    # Initialize the Random Forest classifier
    rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)

    # Train the model
    rf_classifier.fit(X_train, y_train)

    directory = 'Models'
    if not os.path.exists(directory):
        os.makedirs(directory)
    # Save the trained model as a pickle file
    joblib.dump(rf_classifier, 'Models/trained_model_RFC.pkl')

    with open('Models/label_encoder_RFC.pkl', 'wb') as f:
        pickle.dump(label_encoder, f)

    from sklearn.metrics import classification_report, accuracy_score

    # Predict on the testing set
    y_pred = rf_classifier.predict(X_test)

    # Inverse transform the encoded labels to get the actual labels
    actual_labels = label_encoder.inverse_transform(y_test)
    predicted_labels = label_encoder.inverse_transform(y_pred)

    # Print classification report with actual labels
    print(classification_report(actual_labels, predicted_labels))

    # Print accuracy score
    print("Accuracy:", accuracy_score(actual_labels, predicted_labels))

    # End timing
    end_time = time.time()

    # Calculate and print the time taken
    print("Time taken to create the model: {:.2f} seconds".format(end_time - start_time))
