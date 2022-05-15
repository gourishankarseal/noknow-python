"""
Extremely simple example of NoKnow ZK Proof implementation
"""
from getpass import getpass
from noknow.core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof
from queue import Queue
from threading import Thread
import os
from utils import check_ref_code, get_ce_code
import pandas as pd


def client(iq: Queue, oq: Queue):
    client_zk = ZK.new(curve_name="secp256k1", hash_alg="sha3_256")

    # Create signature and send to server
    ref_code = getpass("Enter Ref Code: ")
    oq.put(ref_code)

    signature = client_zk.create_signature(ref_code) #A
    oq.put(signature.dump())

    # Receive the token from the server
    token = iq.get()

    # Create a proof that signs the provided token and sends to server
    client_input_ref_code_ce_code = getpass("Enter Ref Code,CE Code : ") #x
    proof = client_zk.sign(client_input_ref_code_ce_code, token, signed_by='client').dump()  #m

    # Send the token and proof to the server
    oq.put(proof)

    # Wait for server response!
    print("Success!" if iq.get() else "Failure!")


def server(iq: Queue, oq: Queue):

    data = pd.read_csv('data.csv')
    ref_code = iq.get()
    if not check_ref_code(ref_code, data):
        print('Received invalid Ref Code from client', ref_code, 'exiting')
        os._exit(1)
    else:
        print('Obtained valid ref code from Client')
        # Set up server component
        server_password = get_ce_code(ref_code, data) #x
        server_zk = ZK.new(curve_name="secp384r1", hash_alg="sha3_512")
        server_signature: ZKSignature = server_zk.create_signature(server_password)  #B

        # Load the received signature from the Client
        sig = iq.get()
        client_signature = ZKSignature.load(sig)
        client_zk = ZK(client_signature.params)

        # Create a signed token and send to the client
        token = server_zk.sign(server_password, client_zk.token(), signed_by='server')  # c
        oq.put(token.dump(separator=":"))

        # Get the proof statement from the client
        proof = ZKData.load(iq.get())
        token = ZKData.load(proof.data, ":")

        # In this example, the server signs the token so it can be sure it has not been modified
        if server_zk.verify(token, server_signature):
            oq.put(True)
        else:
            oq.put(False)
            # oq.put(client_zk.verify(proof, client_signature, data=token))


def main():
    q1, q2 = Queue(), Queue()
    threads = [
        Thread(target=client, args=(q1, q2)),
        Thread(target=server, args=(q2, q1)),
    ]
    # for func in [Thread.start, Thread.join]:
    #     for thread in threads:
    #         func(thread)
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()