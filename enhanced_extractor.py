import re
import json
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Load preprocessed MITRE ATT&CK dataset
with open("technique_db.json", "r") as f:
    technique_db = json.load(f)

# Cache for technique details
technique_cache = {}

def extract_attack_tactics_techniques(text: str) -> List[str]:
    # Define a regex pattern to match ATT&CK tactics and techniques
    attack_pattern = r'\b(T\d{4}(?:\.\d{3})?)\b'
    
    # Find all unique matches in the input text
    matches = list(set(re.findall(attack_pattern, text)))
    return sorted(matches)

def get_attack_technique_details(technique_id: str) -> Dict:
    """Fetch details for a specific ATT&CK technique from the preprocessed dataset"""
    if technique_id in technique_cache:
        return technique_cache[technique_id]
    
    if technique_id in technique_db:
        result = {
            "name": technique_db[technique_id]["name"],
            "description": technique_db[technique_id]["description"],
            "status": "success"
        }
        technique_cache[technique_id] = result
        return result
    
    return {
        "name": "Unknown",
        "description": "No details found in MITRE ATT&CK database.",
        "status": "not_found"
    }

def extract_and_display():
    extract_button.config(state=tk.DISABLED)
    result_output.delete("1.0", tk.END)
    result_output.insert(tk.END, "Processing...\n")
    root.update()
    
    try:
        input_text = text_input.get("1.0", tk.END).strip()
        
        if not input_text:
            messagebox.showwarning("Input Error", "Please paste some text to analyze.")
            return
        
        technique_ids = extract_attack_tactics_techniques(input_text)
        
        if not technique_ids:
            messagebox.showinfo("No Results", "No ATT&CK Tactics and Techniques found in the text.")
            return
        
        result_output.delete("1.0", tk.END)
        result_output.insert(tk.END, f"Found {len(technique_ids)} unique ATT&CK techniques.\n\n")
        
        completed = 0
        total = len(technique_ids)
        
        # Use ThreadPoolExecutor with fewer workers
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_technique = {
                executor.submit(get_attack_technique_details, technique_id): technique_id 
                for technique_id in technique_ids
            }
            
            for future in as_completed(future_to_technique):
                technique_id = future_to_technique[future]
                try:
                    details = future.result()
                    completed += 1
                    
                    # Update progress every 5 techniques
                    if completed % 5 == 0 or completed == total:
                        result_output.insert(tk.END, f"\nTechnique ID: {technique_id}\n")
                        result_output.insert(tk.END, f"Name: {details['name']}\n")
                        result_output.insert(tk.END, f"Description: {details['description']}\n")
                        result_output.insert(tk.END, "---------------------------------------------\n")
                        root.update()
                except Exception as e:
                    result_output.insert(tk.END, f"Error processing {technique_id}: {str(e)}\n")
                root.update()
                
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
    finally:
        extract_button.config(state=tk.NORMAL)

def export_results():
    """Export results to a text file"""
    results = result_output.get("1.0", tk.END)
    if not results.strip():
        messagebox.showwarning("Export Error", "No results to export.")
        return
    
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w") as f:
            f.write(results)
        messagebox.showinfo("Export Successful", f"Results saved to {file_path}")

# Create the main GUI window
root = tk.Tk()
root.title("MITRE ATT&CK Tactics and Techniques Extractor")
root.geometry("800x600")

# Add menu bar
menubar = tk.Menu(root)
root.config(menu=menubar)

# File menu
file_menu = tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Clear All", command=lambda: [text_input.delete("1.0", tk.END), 
                                                        result_output.delete("1.0", tk.END)])
file_menu.add_command(label="Export Results", command=export_results)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)

# Input frame
input_frame = tk.Frame(root)
input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

tk.Label(input_frame, text="Paste your unstructured cyber threat report text here:").pack(anchor='w')
text_input = scrolledtext.ScrolledText(input_frame, width=90, height=10)
text_input.pack(fill=tk.BOTH, expand=True)

# Extract button
extract_button = tk.Button(root, text="Extract ATT&CK Tactics and Techniques", 
                          command=extract_and_display, 
                          bg='#4CAF50', 
                          fg='white', 
                          pady=5)
extract_button.pack(pady=10)

# Result frame
result_frame = tk.Frame(root)
result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

tk.Label(result_frame, text="Extracted ATT&CK Tactics and Techniques:").pack(anchor='w')
result_output = scrolledtext.ScrolledText(result_frame, width=90, height=20)
result_output.pack(fill=tk.BOTH, expand=True)

# Run the GUI
root.mainloop()