import pandas as pd


def check_ref_code(ref, data):
    if data[data.identification == ref].shape[0] > 0:
        return True
    else:
        return False


def get_ce_code(ref, data):

    if check_ref_code(ref, data):
        ce_code = data.loc[data.identification == ref,'CE_CODE'].values[0]
        # print('CE CODE found',ce_code)
    else:
        print('CE_CODE not found')
        return


if __name__ == "__main__":
    ref = '13aq'  # ABDND NQZSCFT
    data = pd.read_csv('data.csv')
    get_ce_code(ref, data)