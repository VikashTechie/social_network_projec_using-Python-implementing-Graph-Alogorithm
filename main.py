import tkinter as tk
from tkinter import ttk, messagebox
from collections import deque
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class SocialNetwork:
    def __init__(self):
        self.graph = nx.Graph()
        self.users = {}
        self.color_themes = {
            "Ocean": {
                "node": "blue",
                "edge": "#7f8c8d",
                "highlight": "#e74c3c",
                "bg": "#ecf0f1",
                "text": "#2c3e50",
                "path_bg": "#d6eaf8"
            },
            "Forest": {
                "node": "#27ae60",
                "edge": "#7f8c8d",
                "highlight": "#e67e22",
                "bg": "#f5f5f5",
                "text": "#34495e",
                "path_bg": "#d5f5e3"
            },
            "Royal": {
                "node": "#9b59b6",
                "edge": "#95a5a6",
                "highlight": "#f1c40f",
                "bg": "#f9f9f9",
                "text": "#2c3e50",
                "path_bg": "#e8daef"
            }
        }
        self.current_theme = "Ocean"
    
    def add_user(self, user_id, name):
        if user_id in self.users:
            raise ValueError(f"User ID {user_id} already exists")
        self.users[user_id] = name
        self.graph.add_node(user_id, name=name)
        
    def add_friendship(self, user1, user2, strength=1):
        if user1 not in self.users or user2 not in self.users:
            raise ValueError("One or both users don't exist")
        self.graph.add_edge(user1, user2, strength=strength)
        
    def get_mutual_friends(self, user1, user2):
        if user1 not in self.users or user2 not in self.users:
            raise ValueError("One or both users don't exist")
        return list(nx.common_neighbors(self.graph, user1, user2))
        
    def set_theme(self, theme_name):
        if theme_name in self.color_themes:
            self.current_theme = theme_name
            
    def find_shortest_path(self, user1, user2):
    # Bidirectional BFS for unweighted paths
        if user1 not in self.graph or user2 not in self.graph:
            return None
            
        if user1 == user2:
            return [user1]
            
        queue_f = deque([(user1, [user1])])
        queue_b = deque([(user2, [user2])])
        visited_f = {user1: [user1]}
        visited_b = {user2: [user2]}
        
        while queue_f and queue_b:
            # Forward BFS step
            current_f, path_f = queue_f.popleft()
            for neighbor in self.graph.neighbors(current_f):
                if neighbor in visited_b:
                    return path_f + visited_b[neighbor][::-1]  # Ensure full path is included
                if neighbor not in visited_f:
                    visited_f[neighbor] = path_f + [neighbor]
                    queue_f.append((neighbor, path_f + [neighbor]))

            # Backward BFS step
            current_b, path_b = queue_b.popleft()
            for neighbor in self.graph.neighbors(current_b):
                if neighbor in visited_f:
                    return visited_f[neighbor] + path_b[::-1]  # Ensure full path is included
                if neighbor not in visited_b:
                    visited_b[neighbor] = path_b + [neighbor]
                    queue_b.append((neighbor, path_b + [neighbor]))

        return None

    def find_weighted_path(self, user1, user2):
        """Dijkstra's algorithm for weighted paths"""
        try:
            return nx.dijkstra_path(self.graph, user1, user2, weight='strength')
        except nx.NetworkXNoPath:
            return None
        except nx.NodeNotFound:
            return None

    def get_user_list(self):
        return [(uid, name) for uid, name in self.users.items()]
    
    def get_friendships(self):
        return [(u, v, d['strength']) for u, v, d in self.graph.edges(data=True)]

class SocialNetworkApp:
    def __init__(self, root):
        self.root = root
        self.sn = SocialNetwork()
        self.setup_ui()
        
    def setup_ui(self):
        # Window Configuration
        self.root.title("Social Network Visualizer")
        self.root.geometry("1000x700+100+100")
        self.root.resizable(False,False )
        self.root.configure(bg=self.sn.color_themes[self.sn.current_theme]["bg"])
        
        # Custom Styling
        self.setup_styles()
        
        # Main Container Frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left Control Panel Container
        control_container = ttk.Frame(main_frame, width=280)
        control_container.pack(side=tk.LEFT, fill=tk.Y, padx=(0,10))
        
        # Create Canvas and Scrollbar for control panel
        self.control_canvas = tk.Canvas(control_container, 
                                      bg=self.sn.color_themes[self.sn.current_theme]["bg"],
                                      width=270,
                                      highlightthickness=0)
        scrollbar = ttk.Scrollbar(control_container, 
                                orient=tk.VERTICAL, 
                                command=self.control_canvas.yview)
        self.scrollable_frame = ttk.Frame(self.control_canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.control_canvas.configure(
                scrollregion=self.control_canvas.bbox("all")
            )
        )
        
        self.control_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.control_canvas.configure(yscrollcommand=scrollbar.set)
        
        self.control_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Right Visualization Area
        self.viz_frame = ttk.Frame(main_frame)
        self.viz_frame.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)
        
        # Add sections to scrollable frame
        self.setup_theme_selector(self.scrollable_frame)
        self.setup_user_section(self.scrollable_frame)
        self.setup_friendship_section(self.scrollable_frame)
        self.setup_mutual_friends_section(self.scrollable_frame)
        self.setup_path_finding_section(self.scrollable_frame)
        self.setup_visualization_button(self.scrollable_frame)
        self.setup_user_list_section(self.scrollable_frame)
        
        # Bind mousewheel for scrolling
        self.control_canvas.bind_all("<MouseWheel>", self._on_mousewheel)
    
    def _on_mousewheel(self, event):
        self.control_canvas.yview_scroll(int(-3*(event.delta/120)), "units")
        
    def setup_styles(self):
        style = ttk.Style()
        theme = self.sn.color_themes[self.sn.current_theme]
        
        style.configure("TFrame", background=theme["bg"])
        style.configure("TLabel", 
                      background=theme["bg"],
                      foreground=theme["text"],
                      font=("Helvetica", 9))
        
        style.configure("TButton",
                      background=theme["node"],
                      foreground="black",
                      font=("Helvetica", 10),
                      padding=6,
                      borderwidth=0)
        style.map("TButton",
                background=[("active", theme["highlight"])])
        
        style.configure("TEntry",
                      fieldbackground="white",
                      foreground="black",
                      insertcolor="black",
                      borderwidth=1,
                      relief="solid")
        
        style.configure("TLabelframe", 
                      background=theme["bg"],
                      foreground=theme["text"])
        style.configure("TLabelframe.Label", 
                      background=theme["bg"],
                      foreground=theme["text"])
        
        # Special style for path finding section
        style.configure("Path.TLabelframe", 
                      background=theme["path_bg"],
                      foreground=theme["highlight"],
                      font=("Helvetica", 10, "bold"),
                      relief=tk.RIDGE,
                      borderwidth=2)
        style.configure("Path.TLabelframe.Label", 
                      background=theme["path_bg"],
                      foreground=theme["highlight"],
                      font=("Helvetica", 10, "bold"))
        
        style.configure("Path.TButton",
                      background=theme["highlight"],
                      foreground="white",
                      font=("Helvetica", 10, "bold"),
                      padding=6)
        style.map("Path.TButton",
                background=[("active", theme["node"])])
        
    def setup_theme_selector(self, parent):
        theme_frame = ttk.LabelFrame(parent, text="COLOR THEME")
        theme_frame.pack(fill=tk.X, pady=(0,15))
        
        self.theme_var = tk.StringVar(value=self.sn.current_theme)
        
        for theme_name in self.sn.color_themes:
            rb = ttk.Radiobutton(theme_frame, 
                                text=theme_name,
                                variable=self.theme_var,
                                value=theme_name,
                                command=self.change_theme)
            rb.pack(anchor=tk.W, padx=5, pady=2)
        
    def change_theme(self):
        """Handle theme change event"""
        self.sn.set_theme(self.theme_var.get())
        self.setup_styles()
        self.root.configure(bg=self.sn.color_themes[self.sn.current_theme]["bg"])
        self.visualize_graph()
        
    def setup_user_section(self, parent):
        user_frame = ttk.LabelFrame(parent, text="ADD USER")
        user_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(user_frame, text="User ID:").pack(anchor=tk.W)
        self.user_id_entry = ttk.Entry(user_frame)
        self.user_id_entry.pack(fill=tk.X, pady=2)
        
        ttk.Label(user_frame, text="Name:").pack(anchor=tk.W)
        self.user_name_entry = ttk.Entry(user_frame)
        self.user_name_entry.pack(fill=tk.X, pady=2)
        
        ttk.Button(user_frame, 
                 text="Add User", 
                 command=self.add_user).pack(pady=5, fill=tk.X)
        
    def setup_user_list_section(self, parent):
        list_frame = ttk.LabelFrame(parent, text="USER LIST")
        list_frame.pack(fill=tk.BOTH, pady=5, expand=True)

        # Treeview widget to display users (ID and Name)
        self.user_tree = ttk.Treeview(
            list_frame, 
            columns=("ID", "Name"), 
            show="headings",
            height=5
        )
        self.user_tree.heading("ID", text="User ID")
        self.user_tree.heading("Name", text="Name")
        self.user_tree.column("ID", width=100)
        self.user_tree.column("Name", width=150)

        # Scrollbar for the Treeview
        scrollbar = ttk.Scrollbar(
            list_frame, 
            orient=tk.VERTICAL, 
            command=self.user_tree.yview
        )
        self.user_tree.configure(yscrollcommand=scrollbar.set)

        # Pack the Treeview and Scrollbar
        self.user_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Populate the list initially
        self.update_user_list()

    def update_user_list(self):
        #  Refreshes the user list in the Treeview
        self.user_tree.delete(*self.user_tree.get_children())  # Clear existing entries
        for user_id, name in self.sn.get_user_list():
            self.user_tree.insert("", tk.END, values=(user_id, name))
        
    def setup_friendship_section(self, parent):
        friend_frame = ttk.LabelFrame(parent, text="ADD FRIENDSHIP")
        friend_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(friend_frame, text="User 1 ID:").pack(anchor=tk.W)
        self.user1_entry = ttk.Entry(friend_frame)
        self.user1_entry.pack(fill=tk.X, pady=2)
        
        ttk.Label(friend_frame, text="User 2 ID:").pack(anchor=tk.W)
        self.user2_entry = ttk.Entry(friend_frame)
        self.user2_entry.pack(fill=tk.X, pady=2)
        
        ttk.Label(friend_frame, text="Strength (1-10):").pack(anchor=tk.W)
        self.strength_entry = ttk.Entry(friend_frame)
        self.strength_entry.pack(fill=tk.X, pady=2)
        self.strength_entry.insert(0, "1")
        
        ttk.Button(friend_frame, 
                 text="Connect Users", 
                 command=self.add_friendship).pack(pady=5, fill=tk.X)
    
    def setup_mutual_friends_section(self, parent):
        mutual_frame = ttk.LabelFrame(parent, text="FIND MUTUAL FRIENDS")
        mutual_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(mutual_frame, text="User 1 ID:").pack(anchor=tk.W)
        self.mutual_user1 = ttk.Entry(mutual_frame)
        self.mutual_user1.pack(fill=tk.X, pady=2)
        
        ttk.Label(mutual_frame, text="User 2 ID:").pack(anchor=tk.W)
        self.mutual_user2 = ttk.Entry(mutual_frame)
        self.mutual_user2.pack(fill=tk.X, pady=2)
        
        ttk.Button(mutual_frame,
                 text="Find Mutual Friends",
                 command=self.show_mutual).pack(pady=5, fill=tk.X)
    
    def setup_path_finding_section(self, parent):
        path_frame = ttk.LabelFrame(parent, text="PATH FINDING", style='Path.TLabelframe')
        path_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(path_frame, text="From User ID:").pack(anchor=tk.W)
        self.path_user1 = ttk.Entry(path_frame)
        self.path_user1.pack(fill=tk.X, pady=2)
        
        ttk.Label(path_frame, text="To User ID:").pack(anchor=tk.W)
        self.path_user2 = ttk.Entry(path_frame)
        self.path_user2.pack(fill=tk.X, pady=2)
        
        ttk.Button(path_frame, 
                 text="Find Shortest Path (Unweighted)", 
                 command=self.show_unweighted_path).pack(pady=5, fill=tk.X)
                 
        ttk.Button(path_frame, 
                 text="Find Strongest Path (Weighted)", 
                 command=self.show_weighted_path).pack(pady=5, fill=tk.X)
    
    def setup_visualization_button(self, parent):
        ttk.Button(parent,
                 text="Show Full Network",
                 command=lambda: self.visualize_graph()).pack(fill=tk.X, pady=5)
    
    def add_user(self):
        user_id = self.user_id_entry.get().strip()
        name = self.user_name_entry.get().strip()
        if user_id and name:
            try:
                self.sn.add_user(user_id, name)
                messagebox.showinfo("Success", f"User {name} added!")
                self.user_id_entry.delete(0, tk.END)
                self.user_name_entry.delete(0, tk.END)
                self.update_user_list()
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Please enter both ID and name")
            
    def add_friendship(self):
        user1 = self.user1_entry.get().strip()
        user2 = self.user2_entry.get().strip()
        strength = self.strength_entry.get().strip()
        
        try:
            strength = max(1, min(10, int(strength)))
        except ValueError:
            strength = 1
            
        if user1 and user2:
            try:
                self.sn.add_friendship(user1, user2, strength)
                messagebox.showinfo("Success", f"Friendship added with strength {strength}!")
                self.user1_entry.delete(0, tk.END)
                self.user2_entry.delete(0, tk.END)
                self.strength_entry.delete(0, tk.END)
                self.strength_entry.insert(0, "1")
                self.visualize_graph()
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Please enter both user IDs")
            
    def show_mutual(self):
        user1 = self.mutual_user1.get().strip()
        user2 = self.mutual_user2.get().strip()
        if user1 and user2:
            try:
                mutual = self.sn.get_mutual_friends(user1, user2)
                self.visualize_graph(mutual if mutual else [])
                msg = f"Mutual friends between {user1} and {user2}:\n\n" + "\n".join(mutual) if mutual else "No mutual friends found"
                messagebox.showinfo("Mutual Friends", msg)
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Please enter both user IDs")
    
    def show_unweighted_path(self):
        user1 = self.path_user1.get().strip()
        user2 = self.path_user2.get().strip()
        if user1 and user2:
            path = self.sn.find_shortest_path(user1, user2)
            self.visualize_path(path, "Shortest Path (BFS)")
        else:
            messagebox.showerror("Error", "Please enter both user IDs")
    
    def show_weighted_path(self):
        user1 = self.path_user1.get().strip()
        user2 = self.path_user2.get().strip()
        if user1 and user2:
            path = self.sn.find_weighted_path(user1, user2)
            self.visualize_path(path, "Strongest Path (Dijkstra)")
        else:
            messagebox.showerror("Error", "Please enter both user IDs")
    
    def visualize_path(self, path, title):
        if not path:
            messagebox.showerror("Error", "No path exists between these users")
            return
            
        highlight_nodes = set(path)
        highlight_edges = [(path[i], path[i+1]) for i in range(len(path)-1)]
        
        self._visualize_graph(highlight_nodes, highlight_edges, title)
        
        # Show path as text
        path_names = [self.sn.users.get(node, node) for node in path]
        messagebox.showinfo("Path Found", " → ".join(path_names))
    
    def visualize_graph(self, highlight_nodes=None):
        self._visualize_graph(highlight_nodes if highlight_nodes else set(), [], "Social Network Graph")
    
    def _visualize_graph(self, highlight_nodes, highlight_edges, title):
        # Clear previous visualization
        for widget in self.viz_frame.winfo_children():
            widget.destroy()
            
        if not self.sn.graph.nodes():
            empty_label = ttk.Label(self.viz_frame, text="No users in the network yet!")
            empty_label.pack(expand=True)
            return
            
        fig = plt.figure(figsize=(8, 6), facecolor=self.sn.color_themes[self.sn.current_theme]["bg"])
        ax = fig.add_subplot(111, facecolor=self.sn.color_themes[self.sn.current_theme]["bg"])
        
        pos = nx.spring_layout(self.sn.graph, k=0.3, iterations=50)
        theme = self.sn.color_themes[self.sn.current_theme]
        
        # Draw all nodes
        nx.draw_networkx_nodes(
            self.sn.graph, pos,
            node_size=500,
            node_color=[theme["highlight"] if node in highlight_nodes 
                       else theme["node"] for node in self.sn.graph.nodes()],
            alpha=0.9,
            linewidths=2,
            edgecolors="#333333"
        )
        
        # Draw all edges
        edge_colors = []
        edge_widths = []
        for u, v, d in self.sn.graph.edges(data=True):
            if (u, v) in highlight_edges or (v, u) in highlight_edges:
                edge_colors.append(theme["highlight"])
                edge_widths.append(3)
            else:
                edge_colors.append(theme["edge"])
                edge_widths.append(1 + d['strength'] * 0.5)
        
        nx.draw_networkx_edges(
            self.sn.graph, pos,
            width=edge_widths,
            edge_color=edge_colors,
            alpha=0.6
        )
        
        # Draw edge labels (strength values)
        edge_labels = {(u, v): d['strength'] for u, v, d in self.sn.graph.edges(data=True)}
        nx.draw_networkx_edge_labels(
            self.sn.graph, pos,
            edge_labels=edge_labels,
            font_color=theme["text"],
            font_size=8
        )
        
        # Draw labels
        nx.draw_networkx_labels(
            self.sn.graph, pos,
            labels=self.sn.users,
            font_size=10,
            font_color="white",
            bbox=dict(
                facecolor=theme["node"],
                edgecolor="none",
                alpha=0.5,
                boxstyle="round,pad=0.3"
            )
        )
        
        ax.set_title(title, color=theme["text"], fontsize=12, pad=20)
        ax.axis("off")
        plt.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, master=self.viz_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    
    

if __name__ == "__main__":
    root = tk.Tk()
    app = SocialNetworkApp(root)
    root.mainloop()