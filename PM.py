import pickle
import pandas as pd
import joblib

def predict(model_path, label_encoder_path, generated_data, savefile):
    # Load the model from the .pkl file
    model = joblib.load(model_path)
    #Load the label encoder from the .pkl file
    with open(label_encoder_path, 'rb') as f:
        label_encoder = pickle.load(f)

    # Load the new data
    new_data = pd.DataFrame(generated_data)

    # Preprocessing steps to remove rows with specified values
    columns_to_check = ["proto", "service", "state", "spkts", "dpkts", 
                        "sbytes", "dbytes", "swin", "dwin", "stcpb", "dtcpb"]

    # Remove rows where any of the specified columns have value "-"
    for column in columns_to_check:
        new_data = new_data[new_data[column] != "-"]

    # If 'Generic' values are found, remove rows with 'Generic' values in the 'service' column
    if 'service' in new_data.columns:
        new_data = new_data[new_data['service'] != 'Generic']

    # One-hot encode categorical variables
    new_data = pd.get_dummies(new_data, columns=["proto", "service", "state"], drop_first=True)

    # Ensure the columns in new_data match the columns in the model's training data
    # Reorder the columns to match the order of the training data
    new_data = new_data.reindex(columns=model.feature_names_in_.tolist(), fill_value=False)

    # Make predictions
    predictions = model.predict(new_data)

    # Map the encoded predictions back to their original categories
    predicted_categories = label_encoder.inverse_transform(predictions)

    # Add the predicted categories to the new_data DataFrame
    new_data['attack_cat'] = predicted_categories

    # Assign labels based on attack category
    new_data['label'] = ((new_data['attack_cat'] != "Normal") & (new_data['attack_cat'] != "Generic")).astype(int)


    # Save the results to a CSV file
    if savefile == "y":
        new_data.to_csv("Results/Predictions/predictions.csv", index=False)