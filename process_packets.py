import joblib 
import pandas as pd
from keras.models import load_model
from sklearn.preprocessing import LabelEncoder, StandardScaler
import numpy as np
import threading
import telegram
class Process:
    def __init__(self):
        self.df = pd.DataFrame()
        self.X_transformed = None
        self.load_and_process_data()
        
    def load_and_process_data(self):
        try:
            self.df = pd.read_csv("extracted_packets.csv", sep=",", names=[
                "duration", "protocoltype", "service", "flag", "srcbytes", "dstbytes", "wrongfragment", "hot", 
                "loggedin", "numcompromised", "rootshell", "suattempted", "numroot", "numfilecreations",
                "numshells", "numaccessfiles", "ishostlogin", "isguestlogin", "count", "srvcount", "serrorrate", 
                "srvserrorrate", "rerrorrate", "srvrerrorrate", "samesrvrate", "diffsrvrate", "srvdiffhostrate",
                "dsthostcount", "dsthostsrvcount", "dsthostsamesrvrate", "dsthostdiffsrvrate", 
                "dsthostsamesrcportrate", "dsthostsrvdiffhostrate", "dsthostserrorrate", "dsthostsrvserrorrate",
                "dsthostrerrorrate", "dsthostsrvrerrorrate", "lastflag"
            ])
            self.df=self.df.fillna(0)
            
            le = LabelEncoder()
            self.df['protocoltype'] = le.fit_transform(self.df['protocoltype'])
            self.df['service'] = le.fit_transform(self.df['service'])
            self.df['flag'] = le.fit_transform(self.df['flag'])
            
            scaler = StandardScaler()
            self.X_transformed = scaler.fit_transform(self.df)
        except Exception as e:
            print(f"Error processing data: {e}")        	

    def count_zeros_greater_than_ones(self, arr):
        arr = list(arr)
        count_zeros = arr.count(0)
        count_ones = arr.count(1)
        return count_zeros > count_ones
    """
    def count_trues_greater_than_falses(self, bool_list):
        bool_list = list(bool_list)
        
        count_trues = bool_list.count(True)
        count_falses = bool_list.count(False)
        return count_trues > count_falses
    """
    def SVM(self):
        return False

    def rf(self):
        try:
            rf = joblib.load("random_forest_model.pkl")
            array = rf.predict(self.X_transformed)
            print("RF:",array)
            c = self.count_zeros_greater_than_ones(array)
            print("the bool of RF:",c)
            return c
        except Exception as e:
            print(f"Error in Random Forest prediction: {e}")
            return False
    """
    def neural_network(self):
        try:
            nn_model = load_model('neural_network_model.h5')
            array = nn_model.predict(self.X_transformed)
            print("NN:",array)
            c = self.count_trues_greater_than_falses(np.round(array))
            return c
        except Exception as e:
            print(f"Error in Neural Network prediction: {e}")
            return False
    """
    def logic(self):
        try:
            if self.rf() or self.SVM():
                print("There is an attack")
                telegram.send_telegram_message("There is an Attack !!!!!!!")
                th=threading.Thread(target=telegram.main())
                th.start()
            else:
                print("No attack detected")
        except Exception as e:
            print(f"Error in logic method: {e}")

# Example usage:


