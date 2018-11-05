from sklearn.externals import joblib
import numpy as np


features=[113757377,545,0,0,0,0,0,0,0,0,0,0,0,0,4.790898088,209112.8254,1395543.434,2.08E+07,0,1.14E+08,209112.8254,1395543.434,2.08E+07,0,0,0,0,0,0,0,0,0,0,0, 0,4.790898088,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,545, 0,0,0,-1,-1,0,0,9361828.6,7324645.883,1.89E+07,19,1.22E+07,6935824.002,2.08E+07,5504997]
a = np.array(features)

def classify(feature):


    a=np.reshape(feature,(1,76))
    print(a.shape)
    print(a)
    '''''''''
    f=np.array(features)
    print (f)
    f=np.reshape(f,1,76)
    #f=np.ndarray.flatten('C')
    print(len(features))
    '''''
    model = joblib.load('C:/Users/MoatazYassin/PycharmProjects/GP/mybaby.pk1')
    result =model.predict(a)
    print(result)
    return result