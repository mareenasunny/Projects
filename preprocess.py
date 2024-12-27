import pandas as pd
import matplotlib.pyplot as plt
plt.style.use('ggplot')
import warnings
warnings.filterwarnings('ignore')
def preprocessing(data):
    data[['Start time', 'Last time']] = data['Time'].str.split('-', expand=True)
    df = data.drop(['.', 'Time'], axis=1)
    def calculate_difference(start_time, last_time):
        return int(int(last_time) - int(start_time))
    df['Duration'] = df.apply(lambda row: calculate_difference(row['Start time'], row['Last time']), axis=1)
    df['Protocol'] = df['Protocol'].str.upper().str.strip()
    df['Attack category'] = df['Attack category'].str.upper().str.strip()
    df['Attack category'] = df['Attack category'].str.strip().replace('BACKDOORS', 'BACKDOOR')
    df['Attack category'] = df['Attack category'].str.capitalize()
    df["Attack subcategory"] = df["Attack subcategory"].fillna("Not Registered")
    df["Attack subcategory"] = df["Attack subcategory"].replace(" ", "Not Registered")
    df = df.drop(df[df.duplicated()].index)
    invalid_SP = (df['Source Port'] < 0) | (df['Source Port'] > 65535)
    invalid_DP = (df['Destination Port'] < 0) | (df['Destination Port'] > 65535)
    df = df[~(invalid_SP | invalid_DP)].reset_index(drop=True)
    df['Start time'] = pd.to_datetime(df['Start time'], unit='s')
    df['Last time'] = pd.to_datetime(df['Last time'], unit='s')
    return df

