import json
import imp
import os

# Remove when transferred to server
from flask import Flask
from flask import render_template
from flask import request

# Remove when transferred to server
app = Flask(__name__)

# Database integration
# from cassandra.cluster import Cluster

# lsof -i :5000


"""
# Ingestion integration
from kafka import SimpleProducer, KafkaClient

# Start zookeeper: bin/zookeeper-server-start.sh config/zookeeper.properties
# Start kafka: bin/kafka-server-start.sh config/server.properties
# Start consumer test: bin/kafka-console-consumer.sh --zookeeper localhost:2181 --topic userevent --from-beginning
# Create topic bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic geodecode-request
# Send test data
# curl -H "Content-Type: application/json" -X POST -d '{"eventType":"user-click","userId":"123"}' http://127.0.0.1:5000/producer/
@app.route("/producer/", methods=['POST'])
def producer():
	data = request.get_json()
	# To send messages synchronously
	kafka = KafkaClient('localhost:9092')
	producer = SimpleProducer(kafka)
	# listToSend = [d['eventType'] + ',' + d['userId'] for d in data]
	# Note that the application is responsible for encoding messages to type bytes
	dataToSend = data['geodecode-request'] + ',' + data['userId']
	producer.send_messages(b'userevent', dataToSend.encode('utf-8') )
"""

@app.route("/")
def hello():
	return render_template('index.html')

@app.route("/geodecode/", methods=['POST','GET'])
def geodecode():
	# Input sanity checks
	#ip_address = request.args.get('ipaddress', '')
	#data = request.get_json()
	#data['ip']
	return json.dumps([{'address':'1 Infinite Loop', \
						'city':'Paradise City', \
						'organization':'SVDS', \
						'longitude':0.0, \
						'latitude':0.0}])

if __name__ == "__main__":
    app.run(debug=True)

