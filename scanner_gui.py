import tkinter as tk
from tkinter import ttk, messagebox
import threading
import wmi
import subprocess
import csv
import os
from time import sleep, time
from tkinter import filedialog
from concurrent.futures import ThreadPoolExecutor

# Variáveis globais de controle para a varredura
scan_in_progress = False
# Lista para armazenar os resultados
results = []
# Variável para armazenar o tempo de início
start_time = 0

# Função para testar a conectividade do IP
def ping_host(ip):
    try:
        response = subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return response.returncode == 0
    except Exception as e:
        log_message(f"Erro ao pingar {ip}: {e}")
        return False

# Função para coletar as informações do sistema remoto
def get_system_info(ip, username, password):
    try:
        import pythoncom
        pythoncom.CoInitialize()

        c = wmi.WMI(computer=ip, user=username, password=password)
        system_info = c.Win32_ComputerSystem()[0]
        os_info = c.Win32_OperatingSystem()[0]
        cpu_info = c.Win32_Processor()[0]
        mem_info = c.Win32_PhysicalMemory()
        disk_info = c.Win32_LogicalDisk()

        total_mem = sum([int(m.Capacity) for m in mem_info if m.Capacity])  
        total_disk = sum([int(d.Size) for d in disk_info if d.DriveType == 3])

        system_data = {
            'IP': ip,
            'NomeComputador': system_info.Name,
            'CPU': cpu_info.Name,
            'MemoriaRAM': round(total_mem / (1024**3), 2),
            'SistemaOperacional': os_info.Caption,
            'UsuarioAtual': system_info.UserName,
            'Armazenamento': round(total_disk / (1024**3), 2),
        }
        return system_data
    except Exception:
        log_message(f"Erro ao conectar ao IP {ip}!")
        return None

# Função para varrer um único IP
def scan_ip(ip, username, password):
    global scan_in_progress
    log_message(f"Verificando IP: {ip}")

    if scan_in_progress:
        if ping_host(ip):
            log_message(f"Conectado ao IP: {ip}")
            system_data = get_system_info(ip, username, password)
            return system_data if system_data else None
        else:
            log_message(f"Não foi possível conectar ao IP: {ip}!")
    else:
        log_message("Varredura cancelada.")
        return None

    return None

def scan_network_and_collect_data(start_ip, end_ip, username, password):
    global scan_in_progress, start_time, progress_bar
    results = []

    start_parts = list(map(int, start_ip.split('.')))
    end_parts = list(map(int, end_ip.split('.')))

    if start_parts > end_parts:
        log_message("Erro: O IP inicial não pode ser maior que o IP final.")
        return

    # Lista de IPs a escanear
    ip_list = [
        f"{start_parts[0]}.{start_parts[1]}.{i}.{j}"
        for i in range(start_parts[2], end_parts[2] + 1)
        for j in range((start_parts[3] if i == start_parts[2] else 0), 
                       (end_parts[3] if i == start_parts[2] else 255) + 1)
    ]

    # Iniciar a varredura
    start_time = time()

    # Atualiza a barra de progresso para o número total de IPs
    progress_bar["maximum"] = len(ip_list)
    progress_bar["value"] = 0

    # Executa varredura em paralelo
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_results = [executor.submit(scan_ip, ip, username, password) for ip in ip_list]
        for idx, future in enumerate(future_results):
            if not scan_in_progress:
                log_message("Varredura cancelada.")
                return
            result = future.result()
            if result:
                results.append(result)
                update_table(results)

            # Atualiza a barra de progresso independentemente do sucesso ou falha
            progress_bar["value"] = idx + 1
            root.update_idletasks()
    # Marca o tempo de término da varredura
    end_time = time()
    # Calcula a duração
    duration = round(end_time - start_time, 2)
    log_message(f"\nVarredura concluída! Tempo de execução: {duration} segundos.")

# Função para iniciar a varredura
def start_scan():
    global scan_in_progress
    scan_in_progress = True

    start_ip = start_ip_entry.get()
    end_ip = end_ip_entry.get()
    username = username_entry.get()
    password = password_entry.get()

    if not start_ip or not end_ip or not username or not password:
        messagebox.showwarning("Atenção", "Todos os campos são obrigatórios!")
        return

    log_text.delete("1.0", tk.END)
    thread = threading.Thread(target=scan_network_and_collect_data, args=(start_ip, end_ip, username, password))
    thread.start()

# Função para exportar os resultados para CSV
def export_to_csv():
    if results:
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])

        if file_path:
            keys = results[0].keys()
            try:
                with open(file_path, mode='w', newline='', encoding='utf-8') as file:
                    writer = csv.DictWriter(file, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows(results)
                messagebox.showinfo("Sucesso", f"Inventário exportado para {file_path}")
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao salvar o arquivo: {e}")
        else:
            messagebox.showwarning("Atenção", "Nenhum arquivo selecionado.")
    else:
        messagebox.showwarning("Atenção", "Nenhum dado para exportar.")

# Função para exibir mensagens na área de log
def log_message(msg):
    log_text.insert(tk.END, msg + "\n")
    log_text.see(tk.END)

# Função para atualizar a tabela com os resultados
def update_table(results):
    for row in table.get_children():
        table.delete(row)
    
    for item in results:
        table.insert("", tk.END, values=list(item.values()))

# Função para cancelar a varredura
def cancel_scan():
    global scan_in_progress
    scan_in_progress = False
    log_message("Varredura cancelada.")

# Criar a janela principal
root = tk.Tk()
root.title("Scanner de Hardware em Rede")
root.geometry("1250x850")

# Configuração do grid para permitir expansão da largura
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)

# Frame para os campos de entrada
log_frame = tk.Frame(root)
log_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

# Campos de entrada
tk.Label(root, text="IP Inicial:").grid(row=0, column=0, padx=5, pady=10, sticky="e")
start_ip_entry = tk.Entry(root, width=20)
start_ip_entry.grid(row=0, column=1, padx=5, pady=10, sticky="w")

tk.Label(root, text="IP Final:").grid(row=1, column=0, padx=5, pady=10, sticky="e")
end_ip_entry = tk.Entry(root, width=20)
end_ip_entry.grid(row=1, column=1, padx=5, pady=10, sticky="w")

tk.Label(root, text="Usuário:").grid(row=2, column=0, padx=5, pady=10, sticky="e")
username_entry = tk.Entry(root, width=20)
username_entry.grid(row=2, column=1, padx=5, pady=10, sticky="w")

tk.Label(root, text="Senha:").grid(row=3, column=0, padx=5, pady=10, sticky="e")
password_entry = tk.Entry(root, width=20, show="*")
password_entry.bind("<Return>", lambda event: start_scan())
password_entry.grid(row=3, column=1, padx=5, pady=10, sticky="w")

# Botão para iniciar a varredura
scan_button = tk.Button(root, text="Iniciar Varredura", command=start_scan)
scan_button.grid(row=4, column=0, columnspan=2, pady=20)

# Frame para a área de log
log_frame = tk.Frame(root)
log_frame.grid(row=5, column=0, columnspan=2, padx=0, pady=0, sticky="ew")

# Título acima da área de log
log_title = tk.Label(log_frame, text="LOG:", height=1, width=0, bd=0, relief="solid", highlightthickness=1, highlightbackground="grey", highlightcolor="grey")
log_title.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

# Configuração do grid interno para o log
log_frame.grid_columnconfigure(0, weight=1, uniform="equal")
log_frame.grid_columnconfigure(1, weight=1, uniform="equal")

# Área de log
log_text = tk.Text(log_frame, height=10, width=140, bd=0, relief="solid", highlightthickness=1, highlightbackground="grey", highlightcolor="grey")
log_text.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

# Frame para a tabela de resultados
table_frame = tk.Frame(root)
table_frame.grid(row=6, column=0, columnspan=2, padx=0, pady=25, sticky="ew")

# Título acima da tabela de resultados
table_title = tk.Label(table_frame, text="Tabela de Resultados:", height=1, width=0, bd=0, relief="solid", highlightthickness=1, highlightbackground="grey", highlightcolor="grey")
table_title.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

# Configuração do grid interno para o table_frame
table_frame.grid_columnconfigure(0, weight=1, uniform="equal")
table_frame.grid_columnconfigure(1, weight=1, uniform="equal")
table_frame.grid_rowconfigure(1, weight=1, uniform="equal")

# Tabela de resultados
columns = ("IP", "Nome do Computador", "Processador", "Memoria RAM", "Sistema Operacional", "Usuario Atual", "Armazenamento")
table = ttk.Treeview(table_frame, columns=columns, show="headings")
for col in columns:
    table.heading(col, text=col)
    table.column(col, width=140, stretch=True)
table.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")


# Adiciona a barra de progresso no layout
progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.grid(row=8, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

# Frame para os botões (exportar e cancelar)
button_frame = tk.Frame(root)
button_frame.grid(row=7, column=0, columnspan=2, pady=10)

# Botão para exportar CSV
export_button = tk.Button(button_frame, text="Exportar para CSV", command=export_to_csv, width=15)
export_button.grid(row=0, column=0, padx=5, pady=5)

# Botão cancelar operação
cancel_button = tk.Button(button_frame, text="Cancelar", command=cancel_scan, width=15)
cancel_button.grid(row=0, column=1, padx=5, pady=5)

# Iniciar a interface gráfica
root.mainloop()
