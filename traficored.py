#Librerías importadas para utilizar en el código
import argparse
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

#Iniciación de variables
tcp_count = 0
udp_count = 0
source_count = {} #Diccionario key:value
destination_count = {}

#Función de análisis de paquetes
def packet_handler(packet, output_file):
    global tcp_count, udp_count

    #Se extrae día, mes, hora y minuto actual para el nombre del archivo
    timestamp = datetime.now().strftime("%d_%m_%H_%M")
	
    #Loop para revisar todo el tráfico y llenar el archivo base de datos
    with open(output_file, "a") as file:
        if IP in packet:
            src_ip = packet[IP].src
            dest_ip = packet[IP].dst
            file.write(f"{timestamp} - Source IP: {src_ip}, Destination IP: {dest_ip}\n")
            
            #Comparamos las IP de origen y destino para contar cada que se repitan (top 5)
            source_count[src_ip] = source_count.get(src_ip, 0) + 1
            destination_count[dest_ip] = destination_count.get(dest_ip, 0) + 1
            
            #Contamos los paquetes TCP y UDP
            if TCP in packet:
                tcp_count += 1
            elif UDP in packet:
                udp_count += 1
    
    
    protocol = "Unknown Protocol"
    
    #Tamaño del paquete
    packet_size = len(packet)
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        
        #Impresión de pantalla del tráfico capturado
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Packet Size: {packet_size}")

#Función para imprimir el top 5 de IP origen y destino con mayor tráfico
def print_top_5(count_dict, title):

    # tomando los 5 valores mayores
    sorted_dict = dict(sorted(count_dict.items(), key=lambda x: x[1], reverse=True)[:5])
    print(f"\nTop 5 {title} IP addresses:")
    for ip, count in sorted_dict.items():
        print(f"{ip}: {count} packets")

#Función para capturar el tráfico
def capture_packets(interface, timeout):
    filename = f"traffic_capture_{datetime.now().strftime('%d_%m_%H_%M')}.txt"
    sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, filename), timeout=timeout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-time", type=int, help="Total time value in seconds for packet capture")
    parser.add_argument("-interface", help="Network interface to capture packets from")
    args = parser.parse_args()

   
    if args.time and args.interface:
        capture_packets(args.interface, args.time)
        print(f"Total TCP packets captured: {tcp_count}")
        print(f"Total UDP packets captured: {udp_count}")
        print(f"Total packets captured: {tcp_count + udp_count}")
        print_top_5(source_count, "Source")
        print_top_5(destination_count, "Destination")
		
		# imprime los datos que están en la aplicación en Scapy
    else:
        print("Please specify both arguments -time and -interface values.")
