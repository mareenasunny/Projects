import streamlit as st
import pandas as pd
import preprocess,helper
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
from scipy import stats

st.sidebar.title('Cyber Security Analyzer')
uploaded_file = st.sidebar.file_uploader("Choose a file")
if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    df = preprocess.preprocessing(df)
    st.dataframe(df)

    user_list=df['Attack category'].unique().tolist()
    user_list.sort()
    user_list.insert(0,"All")
    selected_user = st.sidebar.selectbox("Analyze attack category wrt",user_list)

    if st.sidebar.button("Show Analysis"):
        num_cases,num_subcat,source,destination=helper.fetch_stats(selected_user,df)
        col1,col2,col3,col4=st.columns(4)
        with col1:
            st.subheader("Total Attacks")
            st.title(num_cases)
        with col2:
            st.subheader("Total Subcategory")
            st.title(num_subcat)
        with col3:
            st.subheader("Number of Source Port")
            st.title(source)
        with col4:
            st.subheader("Number of Destination Port")
            st.title(destination)
        if selected_user=='All':
            st.title("Number of Cyber Attacks")
            x,y,new_df=helper.num_attack(df)
            fig,ax=plt.subplots()
            col1, col2 = st.columns(2)
            with col1:
                ax.bar(x, y, color='red')
                plt.xticks(rotation='vertical')
                st.pyplot(fig)

            with col2:
                st.dataframe(new_df)
        if selected_user=='All':
            st.title("Correlation Graph")
            df_dummies,df2 = helper.corr_graph(df)

            st.subheader("Using Pearson correlation")
            st.write("Measures linear relationship between two continuous variables")

            fig, ax = plt.subplots(figsize=(18,7))
            sns.heatmap(df_dummies.corr(method='pearson'),
                        annot=True, vmin=-1.0, vmax=1.0, cmap=sns.color_palette("RdBu_r", 15))
            plt.xticks(rotation='vertical')
            st.pyplot(fig)

            st.subheader("Using Spearman correlation")
            st.write("Measures non-linear relationship between variables")
            fig, ax = plt.subplots(figsize=(18, 7))
            sns.heatmap(df_dummies.corr(method='spearman'),
                        annot=True, vmin=-1.0, vmax=1.0, cmap=sns.color_palette("RdBu_r", 15))
            plt.xticks(rotation='vertical')
            st.pyplot(fig)



        st.title("Top 5 destination IPs")
        st.write(df['Destination IP'].value_counts()[:5])



        x,y = helper.fetch_graph(selected_user,df)
        st.subheader("Relationship between Start Time and Destination Port for Traffic Directed to IP Address 149.171.126.17")
        st.write("Here, we plotted the relation on the basis of a particular Destination ID")
        fig, ax = plt.subplots(figsize=(18, 7))
        sns.scatterplot(x=x, y=y)
        plt.xlim(left=df['Start time'].min() - timedelta(days=1),
                 right=df['Start time'].max() + timedelta(days=1))
        plt.grid(True)
        st.pyplot(fig)

        st.subheader(
            "Zoom in the left side of Relationship between Start Time and Destination Port for Traffic Directed to IP Address 149.171.126.17 ")
        fig, ax = plt.subplots(figsize=(18, 7))
        sns.scatterplot(x=x, y=y)
        plt.xlim(left=df['Start time'].min(),right=datetime.strptime('15-01-23', '%y-%m-%d'))
        plt.grid(True)
        st.pyplot(fig)

        st.subheader(
            "Zoom in the right side of Relationship between Start Time and Destination Port for Traffic Directed to IP Address 149.171.126.17 ")
        fig, ax = plt.subplots(figsize=(18, 7))
        sns.scatterplot(x=x, y=y)
        plt.xlim(left=datetime.strptime('15-02-18', '%y-%m-%d'),right=df['Start time'].max())
        plt.grid(True)
        st.pyplot(fig)

        st.subheader(
            "Attack Categories on Destination Port Traffic (IP: 149.171.126.17, Ports <= 150) during February 18, 2015 (00:00:00 to 13:00:00)")
        df3=helper.fetch_graph_scatter(selected_user,df)
        fig, ax = plt.subplots(figsize=(18, 10))
        sns.scatterplot(x='Start time', y='Destination Port', hue='Attack category',
                        data=df3[(df3['Destination IP'] == '149.171.126.17') & (df3['Destination Port'] <= 150)],
                        s=65)
        plt.xlim(left=datetime.strptime('15-02-18 00:00:00', '%y-%m-%d %H:%M:%S'),
                 right=datetime.strptime('15-02-18 13:00:00', '%y-%m-%d %H:%M:%S'))
        plt.grid(True)
        st.pyplot(fig)

        st.subheader(
            "Relationship between Destination Port and Duration with Attack Categories for Traffic Directed to IP Address 149.171.126.17")
        fig, ax = plt.subplots(figsize=(18, 10))
        sns.scatterplot(x='Destination Port', y='Duration', hue='Attack category',
                        data=df3[df3['Destination IP'] == '149.171.126.17'])
        plt.grid(True)
        st.pyplot(fig)

        st.subheader(
            "Distribution of Duration Across Attack Categories")
        fig, ax = plt.subplots(figsize=(18, 10))
        sns.violinplot(x='Attack category', y='Duration', data=df3)
        plt.grid(True)
        st.pyplot(fig)

        st.subheader(
            "Number of attacks per hour and attack type")
        df_p1,df_p2,df_p3=helper.heat_map_data(selected_user,df)
        helper.heatmap_graph(df=df_p1, xlabel='Attack category', ylabel='Hour',title='Number of attacks per hour and attack type')


        st.subheader(
            "Percentage of attacks per IP and hour")
        df_p1, df_p2, df_p3 = helper.heat_map_data(selected_user, df)
        helper.heatmap_graph(df = df_p2/df_p2.sum(), xlabel = 'Destination IP', ylabel = 'Hour', title = 'Percentage of attacks per IP and hour')

        st.subheader("Number of attacks per IP and attack type")
        df_p1, df_p2, df_p3 = helper.heat_map_data(selected_user, df)
        helper.heatmap_graph(df = df_p3/df_p3.sum(), xlabel = 'Attack category', ylabel = 'Destination IP', title = 'Number of attacks per IP and attack type')

        df6=helper.fetch_graph_scatter(selected_user,df)
        results = helper.perform_ttest(df6)

        st.subheader("t-tests between the 'Source Port' and 'Destination Port'")
        for attack, pvalue in results.items():
            st.write(f"p-value in T-test for {attack} attack: {pvalue}")

        st.subheader("Relationship between Source Port and Destination Port by Attack Category")
        df6 = helper.fetch_graph_scatter(selected_user, df)
        fig, ax = plt.subplots(figsize=(18, 10))
        sns.scatterplot(x='Source Port',y='Destination Port', hue='Attack category',data=df6)
        plt.grid(True)
        st.pyplot(fig)

        st.subheader("Distribution of Source Ports by Attack Category")
        fig, ax = plt.subplots(figsize=(18, 10))
        sns.stripplot(x='Attack category', y='Source Port', data=df6)
        plt.grid(True)
        st.pyplot(fig)

        st.subheader("Distribution of Destination Ports by Attack Category")
        fig, ax = plt.subplots(figsize=(18, 10))
        sns.stripplot(x='Attack category',y='Destination Port',data=df6)
        plt.grid(True)
        st.pyplot(fig)

        st.subheader("Destination Port Distribution by Attack Category for Different Attacker IPv4 Addresses")
        ips = list(df6['Source IP'].unique())
        f, axes = plt.subplots(2, 2)
        f.set_figheight(10)
        f.set_figwidth(15)

        labels = list(df6['Attack category'].unique())
        for i, ip in enumerate(ips):
            sns.stripplot(x='Attack category', y='Destination Port', data=df6[df6['Source IP'] == ip], order=labels,
                          ax=axes[int(i / 2)][i % 2])
            axes[int(i / 2)][i % 2].set_xlabel('Attack category')
            axes[int(i / 2)][i % 2].set_ylabel('Destination Port')
            axes[int(i / 2)][i % 2].set_title('Destination Port distribution - Attacker IPv4 Address: ' + ip)
            axes[int(i / 2)][i % 2].set_xticklabels(labels, rotation=90)
        plt.tight_layout()
        st.pyplot(f)

        st.subheader("Destination Port Distribution by Attack Category for Various Target IPv4 Addresses")
        ips = list(df6['Destination IP'].unique())
        f, axes = plt.subplots(5, 2)
        f.set_figheight(25)
        f.set_figwidth(15)

        labels = list(df6['Attack category'].unique())

        for i, ip in enumerate(ips):
            sns.stripplot(x='Attack category', y='Destination Port', data=df6[df6['Destination IP'] == ip],
                          order=labels, ax=axes[int(i / 2)][i % 2])
            axes[int(i / 2)][i % 2].set_xlabel('Attack category')
            axes[int(i / 2)][i % 2].set_ylabel('Destination Port')
            axes[int(i / 2)][i % 2].set_title('Destination Port distribution - Target IPv4 Address: ' + ip)
            axes[int(i / 2)][i % 2].set_xticklabels(labels, rotation=90)
        plt.tight_layout()
        st.pyplot(f)



















