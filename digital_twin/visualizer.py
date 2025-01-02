import matplotlib.pyplot as plt
import networkx as nx

class NetworkVisualizer:
    def __init__(self):
        self.pos = None
        
    def visualize(self, graph, output_path):
        plt.clf()
        if not self.pos:
            self.pos = nx.spring_layout(graph)
            
        plt.figure(figsize=(10, 8))
        nx.draw(graph, self.pos,
                with_labels=True,
                node_color='lightblue',
                node_size=500,
                font_size=16,
                font_weight='bold')
                
        plt.savefig(output_path)
        plt.close() 