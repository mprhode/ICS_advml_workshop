# ICS_advml_workshop
Workshop on adversarial ML for an Industrial Control System IDS

The data used here is a subset of a dataset collected by researchers at The University of Coimbra. 

[Original Paper here](https://link.springer.com/chapter/10.1007/978-3-030-05849-4_19): Frazão, I., Abreu, P.H., Cruz, T., Araújo, H. and Simões, P., 2018, September. Denial of service attacks: Detecting the frailties of machine learning algorithms in the classification process. In International Conference on Critical Information Infrastructures Security (pp. 230-235). Springer, Cham. 

- Thank you to the authors for their help labelling the dataset!

## Installation and Preparation
Pre-requisites:
Python3 and <b> about 3GB (or more) of storage </b>

Open a command line terminal 

1. Clone repo

    ```
    git clone https://github.com/mprhode/ICS_advml_workshop.git
    cd ICS_advml_workshop
    ```

2. We recommend using a virtual environment for these workbooks 

   For Mac/Linux with pip:

   ```
   python3 -m venv myvenv
   source myvenv/bin/activate
   pip install -r requirements.txt
   python download_data.py
   ```    
   
