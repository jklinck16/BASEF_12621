import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
import socket



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
        self.citizen_address = set()
        self.globalvar = 0
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
        total_doctor_nodes = []
        for i in range(len(self.chain)):
            total_citizen_nodes.append(self.chain[i]['citizen nodes'])
            total_doctor_nodes.append(self.chain[i]['doctor nodes'])


        neighbours = []
        for element in total_citizen_nodes:
            if isinstance(element, list):
                for value in element:
                    neighbours.append(value)

        for element in total_doctor_nodes:
            if isinstance(element, list):
                for value in element:
                    neighbours.append(value)


        print(neighbours)
        new_chain = None

        max_length = len(self.chain)

        for i in neighbours:
            response = requests.get(f'http://{i}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

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

    def new_transaction(self, sender, recipient, document, n):
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
            'document hash': document,
            'n': n
        })

        return self.last_block['index'] + 1

    def get_permissioned_address(self):
        return self.chain[0]['message']

    def check_document(self, publ_key, priv_key, string1):
        total_transactions = []
        total_individual_transactions = []
        total_individual_transactions_n = []
        total_transactions_sender = []
        total_total = []
        total_total_r = []
        lst1 = []
        lst2 = []
        blocks = []
        n = 0
        for i in range(len(self.chain)):
            total_transactions.append(self.chain[i]['transactions'])
            for value in range(len(self.chain[i]['transactions'])):
                blocks.append(i)
            #for y in range(len(total_transactions)):
                #total_transactions_sender.append(total_transactions[y])
        print(total_individual_transactions)
        for element in total_transactions:
            if isinstance(element, list):
                for value in element:
                    if not value:
                        total_individual_transactions.append('placeholder')
                    else:
                        print('value: ')
                        print(value)
                        total_individual_transactions.append(value)
        print(total_transactions)
        print(total_individual_transactions)
        print(blocks)
        for b in range(len(total_individual_transactions)):
            total_total.append(total_individual_transactions[b]['sender'])
        for c in range(len(total_individual_transactions)):
            total_total_r.append(total_individual_transactions[b]['recipient'])
        print(total_total)
        print(total_total_r)
        for x in range(len(total_total)):
            if str(total_total[x]) == str(publ_key):
                for y in range(len(total_total_r)):
                    if str(total_total_r[y]) == str(priv_key):
                        print(total_total[x])
                        print(blocks[x])
                        print(self.chain[blocks[x]])

                        print('x:')
                        print(blocks[x])
                        print('x-n:')
                        print(blocks[x-n])

                        print('first item:')
                        print(blocks[0])
                        while blocks[x] == blocks[(x-n)]:
                            n += 1
                            if x-n < 0:
                                break

                        print('n:')
                        print(n)
                        print(self.chain[blocks[x]]['transactions'][n-1]['document hash'])
                        lst1.append(self.chain[blocks[x]]['transactions'][n-1]['document hash'])
                        lst2.append(self.chain[blocks[x]]['transactions'][n-1]['n'])

        num = ""
        for b in string1:
            if b.isdigit():
                num = num + b
        num = num[-5:]


        de = ""
        for d in publ_key:
            if d.isdigit():
                de = de + d

        M1s = []

        for i in range(len(lst1)):
            M1 = (int(lst1[i])**int(de)) % int(lst2[i])
            print(lst1[i])
            print(de)
            print(lst2[i])
            print("M1")
            print(M1)
            print("string:")
            print(string1)
            print("num:")
            print(num)
            if int(M1) == int(num):
                return True
                print ("true!")
                break


        return False



    def sign_document(self, priv_key, publ_key, string):
        num = ""
        for i in string:
            if i.isdigit():
                num = num + i
        num = num[-5:]
        de = ""
        for i in publ_key:
            if i.isdigit():
                de = de + i
        def euclid(m, n):
        	if n == 0:
        		return m
        	else:
        		r = m % n
        		return euclid(n, r)
        def exteuclid(a, b):
        	r1 = a
        	r2 = b
        	s1 = int(1)
        	s2 = int(0)
        	t1 = int(0)
        	t2 = int(1)
        	while r2 > 0:
        		q = r1//r2
        		r = r1-q * r2
        		r1 = r2
        		r2 = r
        		s = s1-q * s2
        		s1 = s2
        		s2 = s
        		t = t1-q * t2
        		t1 = t2
        		t2 = t
        	if t1 < 0:
        		t1 = t1 % a
        	return (r1, t1)
        # Enter two large prime
        # numbers p and q
        p = 823
        q = 953
        n = p * q
        Pn = (p-1)*(q-1)
        # Generate encryption key
        # in range 1<e<Pn
        key = []
        for i in range(2, Pn):
        	gcd = euclid(Pn, i)
        	if gcd == 1:
        		key.append(i)
        e = int(de) #was 313
        x = False
        while x == False:
            r, d = exteuclid(Pn, e)
            if r == 1:
                d = int(d)
                print("decryption key is: ", d)
                x = True
            else:
                e += 1
        S = (int(num)**int(priv_key)) % n
        print("num:")
        print(num)
        print("S:")
        print(S)
        print("N:")
        print(n)
        return S, n

    def get_pair(self, string):
        number = int(string)
        digits = [int(d) for d in str(number)]
        key1 = int(str(digits[0])+str(digits[1])+str(digits[2])+str(digits[3])+str(digits[4]))
        key2 = int(digits[5])*int(str(digits[6])+str(digits[7]))
        final_key = key1 + key2 + int(digits[8])

        if final_key >= 100000:
            final_key = final_key/2

        def euclid(m, n):
        	if n == 0:
        		return m
        	else:
        		r = m % n
        		return euclid(n, r)
        def exteuclid(a, b):
        	r1 = a
        	r2 = b
        	s1 = int(1)
        	s2 = int(0)
        	t1 = int(0)
        	t2 = int(1)
        	while r2 > 0:
        		q = r1//r2
        		r = r1-q * r2
        		r1 = r2
        		r2 = r
        		s = s1-q * s2
        		s1 = s2
        		s2 = s
        		t = t1-q * t2
        		t1 = t2
        		t2 = t
        	if t1 < 0:
        		t1 = t1 % a
        	return (r1, t1)
        p = 823
        q = 953
        n = p * q
        Pn = (p-1)*(q-1)
        # Generate encryption key
        # in range 1<e<Pn
        e = int(final_key) #was 313
        x = False
        while x == False:
            r, d = exteuclid(Pn, e)
            if r == 1:
                d = int(d)
                x = True
            else:
                e += 1
        return d, e

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

# globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')


# Instantiate MediRecord blockchain
blockchain = Blockchain()
blockchain.new_block(previous_hash='1', proof=100, message=node_identifier, citizen_nodes="", doctor_nodes="")


@app.route('/mine', methods=['GET'])
def mine():
    print(port)
    doctor_nodes_list1 = []
    doctor_nodes_list = []
    lst = []
    lst2 = []
    for i in range(len(blockchain.chain)):
        doctor_nodes_list1.append(blockchain.chain[i]['doctor nodes'])
        for element in doctor_nodes_list1:
            doctor_nodes_list.append(element)
    print('list 1: ')
    print(doctor_nodes_list)
    if blockchain.globalvar == 0:
        doctor_nodes_list.append('localhost:' + str(port))
        blockchain.globalvar = 1
    for i in range(len(doctor_nodes_list)):
        print(doctor_nodes_list[i])
        print('doctor nodes')
        print(blockchain.doctor_nodes)
        lst.append(doctor_nodes_list[i])
    print(doctor_nodes_list)
    print(lst)
    for element in lst:
        #lst2.append(lst[element])
        #for y in element:
        if len(element)>1:
            for y in range(len(element)):
                if element[y] == 'localhost:' + str(port):
                    element = element[y]
        if type(element) == list:
            str1 = ''
            #if len(element)>=1:
            element = str1.join(element[0])

        print('port1: ')
        print(element)
        print("port2: ")
        print('localhost:' + str(port))
        if str(element) == 'localhost:' + str(port):
            print('yes!')




            last_block = blockchain.last_block
            proof = blockchain.proof_of_work(last_block)


            previous_hash = blockchain.hash(last_block)

            citizen_nodes = list(blockchain.citizen_nodes)
            doctor_nodes = list(blockchain.doctor_nodes)

            block = blockchain.new_block(proof, previous_hash, node_identifier, citizen_nodes, doctor_nodes)

            blockchain.citizen_nodes = set()
            blockchain.doctor_nodes = set()

            response = {
                'message': "New Block Forged",
                'index': block['index'],
                'transactions': block['transactions'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
            }
            return jsonify(response), 200

    return "Error: Node not registered to mine", 400


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

    required = ['text', 'recipient']
    if not all(k in values for k in required):
        return 'Missing values', 400


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

@app.route('/register', methods=['POST'])
def register_individual():
    healthcare_number = request.form['healthcare_number']
    type = request.form['type']
    public = blockchain.get_pair(healthcare_number)
    public_address = public[1]
    private_address = public[0]
    if type == 'c':
        blockchain.citizen_address.add(public_address)
        index = blockchain.new_transaction(public_address, private_address, 100, 100)
    if type == 'd':
        blockchain.doctor_address.add(public_address)
        index = blockchain.new_transaction(public_address, private_address, 50, 50)

    response = {
        'Public Address': public_address,
        'Private Key': private_address,
    }

    return jsonify(response), 201

@app.route('/nodes/register_website', methods=['POST'])
def register_nodes_website():
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

    if str(type) is None:
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


@app.route('/nodes/register_postman', methods=['POST'])
def register_nodes_postman():
    values = request.get_json()

    nodes = values.get('nodes')

    type = values.get('type')

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

@app.route('/sign/new', methods=['POST'])
def sign():
    valid1 = False
    valid2 = False
    document = request.form['docu_text']
    priv_key = request.form['priv_key']
    publ_key = request.form['publ_key']
    recipient = request.form['recipient']
    lst1 = list(blockchain.doctor_address)
    lst2 = list(blockchain.citizen_address)
    print(lst1)
    print(lst2)


    master_lst = []
    second_lst = []
    second_lst_cit = []
    lst_of_doctors = []
    for i in range(len(blockchain.chain)):
        master_lst.append(blockchain.chain[i]['transactions'])
    print(master_lst)
    for element in master_lst:
        if isinstance(element, list):
            for value in element:
                if not value:
                    total_individual_transactions.append('placeholder')
                else:
                    print('value: ')
                    print(value)
                    lst_of_doctors.append(value)
    print(lst_of_doctors)
    for b in range(len(lst_of_doctors)):
        if int(lst_of_doctors[b]['document hash']) == 50:
            second_lst.append(lst_of_doctors[b]['sender'])
        if int(lst_of_doctors[b]['document hash']) == 100:
            second_lst_cit.append(lst_of_doctors[b]['sender'])

    print(second_lst)
    #blockchain.doctor_address.add(sender)




    for i in range(len(second_lst)):
        if int(publ_key) == second_lst[i]:
            valid1 = True
            print('true1')
    for i in range(len(second_lst_cit)):
        if int(recipient) == second_lst_cit[i]:
            valid2 = True
            print('true2')
    if (valid1 == True) and (valid2 == True):
        document1 = blockchain.convert_document(document)
        docu_hash = blockchain.sign_document(priv_key, publ_key, document1)

        index = blockchain.new_transaction(publ_key, recipient, docu_hash[0], docu_hash[1])

        response = {'message': f'Transaction will be added to Block {index}'}
        return jsonify(response), 201
    else:
        return "Error: Either Sender or Recipient is not allowed", 400





@app.route('/sign/check', methods=['POST'])
def check_docu():
    document = request.form['docu_text']
    publ_key_doctor = request.form['publ_key_d']
    publ_key_recipient = request.form['publ_key_r']

    document1 = blockchain.convert_document(document)


    public = blockchain.get_pair(publ_key_recipient)
    publ_key_recipient = public[1]

    docu_hash = blockchain.check_document(publ_key_doctor, publ_key_recipient, document1)

    if docu_hash==True:
        response = {
            'message': 'Valid Document',
        }
    else:
        response = {
            'message': 'Not Valid Document',
        }
    return jsonify(response), 200


if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    print(s.getsockname()[0])
    s.close()

    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    blockchain.register_node('localhost:5000', 'd')
    #mine()
    #blockchain.resolve_conflicts()
    app.run(host='0.0.0.0', port=port)
