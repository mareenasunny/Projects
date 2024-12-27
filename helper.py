import matplotlib.pyplot as plt
import seaborn as sns
import streamlit as st
import pandas as pd
from scipy import stats
def fetch_stats(selected_user,df):
    if selected_user!="All":
        df=df[df['Attack category']==selected_user]
    num_case=df.shape[0]
    num_subcat = df['Attack subcategory'].nunique()
    source=df['Source Port'].nunique()
    destination = df['Destination Port'].nunique()
    return num_case, num_subcat, source, destination

def num_attack(df):
    x = df['Attack category'].value_counts().index
    y = df['Attack category'].value_counts()
    df = round((df['Attack category'].value_counts()/df.shape[0])*100,2).reset_index().rename(columns={'count':'Percent'})
    return x,y,df

def corr_graph(df):
    new_df = df.drop(['Attack subcategory', 'Protocol', 'Source IP', 'Start time', 'Destination IP',
                      'Last time', 'Attack Name', 'Attack Reference','Destination Port Service'], axis=1)
    df_dummies = pd.get_dummies(new_df, columns=['Attack category'])
    return df_dummies,new_df

def fetch_graph(selected_user,df):
    if selected_user!="All":
        df=df[df['Attack category']==selected_user]
    x = df[df['Destination IP'] == '149.171.126.17']['Start time']
    y = df[df['Destination IP'] == '149.171.126.17']['Destination Port']
    return x,y

def fetch_graph_scatter(selected_user,df):
    if selected_user!="All":
        df=df[df['Attack category']==selected_user]
    return df

def heat_map_data(selected_user,df):
    if selected_user!="All":
        df=df[df['Attack category']==selected_user]
    df_pivot = df.copy()
    df_pivot['hour'] = df_pivot.apply(
        lambda row: '0' * (2 - len(str(row['Start time'].hour))) + str(row['Start time'].hour) + ':00:00', axis=1)
    df_p1 = pd.pivot_table(df_pivot, values='Attack Name', index=['hour'], columns=['Attack category'], aggfunc='count')
    df_p2 = pd.pivot_table(df_pivot, values='Attack Name', index=['hour'], columns=['Destination IP'], aggfunc='count')
    df_p3 = pd.pivot_table(df_pivot, values='Attack Name', index=['Destination IP'], columns=['Attack category'],aggfunc='count')
    return df_p1,df_p2,df_p3

def heatmap_graph(df, xlabel, ylabel, title):
    fig, ax = plt.subplots(figsize=(18, 10))
    sns.heatmap(df)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(rotation=90)
    plt.yticks(rotation=0)
    plt.grid(True)
    st.pyplot(fig)

def perform_ttest(df):
    results = {}
    for attack in df['Attack category'].unique():
        df_attack = df[df['Attack category'] == attack].copy()
        statistic, pvalue = stats.ttest_ind(df_attack['Source Port'], df_attack['Destination Port'], equal_var=False)
        results[attack] = pvalue
    return results

