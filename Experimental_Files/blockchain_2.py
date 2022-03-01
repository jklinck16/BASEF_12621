import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request


class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.citizen_nodes = set()
        self.doctor_nodes = set()
        self.permissioned_nodes = set()
        self.doctor_address = set()
        # Create the genesis block


    def register_node(self, address, type):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)

        if type == 'c':
            if parsed_url.netloc:
                self.citizen_nodes.add(parsed_url.netloc)
            elif parsed_url.path:
                # Accepts an URL without scheme like '192.168.0.5:5000'.
                self.citizen_nodes.add(parsed_url.path)
            else:
                raise ValueError('Invalid URL')
        if type == 'd':
            if parsed_url.netloc:
                self.doctor_nodes.add(parsed_url.netloc)
            elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
                self.doctor_nodes.add(parsed_url.path)
            else:
                raise ValueError('Invalid URL')

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """
        total_citizen_nodes = []
        for i in range(len(self.chain)):
            total_citizen_nodes.append(self.chain[i]['citizen nodes'])


        neighbours = []
        for element in total_citizen_nodes:
            if isinstance(element, list):
                for value in element:
                    neighbours.append(value)

        print(neighbours)
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for i in neighbours:
            response = requests.get(f'http://{i}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash, message, citizen_nodes, doctor_nodes):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'message': message,
            'citizen nodes': citizen_nodes,
            'doctor nodes': doctor_nodes,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, document):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param document: Document
        :return: The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'document': document,
        })

        return self.last_block['index'] + 1

    def get_permissioned_address(self):
        return self.chain[0]['message']

    def convert_document(self, string):

        string_type = string[0:10]
        encoded_full = string.encode()
        result_full = hashlib.sha256(encoded_full)
        hexdigest_full = result_full.hexdigest()
        encoded_type = string_type.encode()
        result_type = hashlib.sha256(encoded_type)
        hexdigest_type = result_type.hexdigest()
        if (hexdigest_type == "7ee0a60c0f40ad8e1b4137a8fcda943a0b5da1da9e93e1f8026e2296eb38e8cb"):
            prefix = "0000"
        elif (hexdigest_type == "7ee08d468aebe9234c72219afd1d7b336e80d6b83f2a2cf91c42ba06b298ac17"):
            prefix = "0001"
        elif (hexdigest_type == "e08ea61b95762724b8ff71be1329ab5b2d807bd3638706e33cb2739d7f97dec4"):
            prefix = "0002"
        elif (hexdigest_type == "8c3bbc0c3b6401f195ca7e36849dfb7677c5ad24f4d74ec51b0f29c607a97a7f"):
            prefix = "0003"
        elif (hexdigest_type == "bc27722878ebd6af22ec4c67352dac32834128b351df52f9aa901d4847cc999f"):
            prefix = "0004"
        else:
            prefix = "0005"
        final_str = (prefix + hexdigest_full)[0:64]
        return final_str


    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof

        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')


# Instantiate the Blockchain
blockchain = Blockchain()
blockchain.new_block(previous_hash='1', proof=100, message=node_identifier, citizen_nodes="", doctor_nodes="")


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.new_transaction(
        sender="0",
        recipient=node_identifier,
        document=0000,
    )

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)

    citizen_nodes = list(blockchain.citizen_nodes)
    doctor_nodes = list(blockchain.doctor_nodes)

    block = blockchain.new_block(proof, previous_hash, "", citizen_nodes, doctor_nodes)

    blockchain.citizen_nodes = set()

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200



@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

@app.route('/document/new', methods=['POST'])
def document():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['text', 'recipient']
    if not all(k in values for k in required):
        return 'Missing values', 400


    # Create a new Transaction
    index = blockchain.new_transaction(node_identifier, values['recipient'], blockchain.convert_document(values['text']))

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/nodes/check', methods=['GET'])
def check():
    response = {
        'permissioned_nodes': list(blockchain.citizen_nodes),
    }
    return jsonify(response), 200


@app.route('/balance', methods=['POST'])
def get_balances():
    values = request.get_json()
    addresses = values.get('address')
    if addresses is None:
        return "Error: Please supply a valid list of addresses", 400
    balance = blockchain.get_balance(addresses)
    response = {
        'message': 'The blockchain has been scanned, this wallet has:',
        'balance': balance,
    }

    return jsonify(response), 201

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    node1 = request.form['node1']
    node2 = request.form['node2']
    node3 = request.form['node3']
    node4 = request.form['node4']
    node5 = request.form['node5']
    node6 = request.form['node6']
    node7 = request.form['node7']
    node8 = request.form['node8']
    node9 = request.form['node9']
    node10 = request.form['node10']

    type = request.form['type']

    nodes_full = [node1, node2, node3, node4, node5, node6, node7, node8, node9, node10]
    nodes = list(filter(None, nodes_full))

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    if type is None:
        return "Error: Please supply a valid node type", 400

    if (node_identifier == blockchain.get_permissioned_address()):
        for node in nodes:
            blockchain.register_node(node, type)
    else:
        return "Error: You do not have permssion to add new nodes"

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.citizen_nodes)+list(blockchain.doctor_nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port)
