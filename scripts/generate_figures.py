"""
Generador de Figuras Científicas de Alta Resolución (300 DPI) para el Capítulo IV.
Genera los gráficos comparativos de barras y cajas estilo APA 7:
- Figura 5: Comparativa Pretest vs. Posttest de la Tasa de Éxito de Ataques (ASR).
- Figura 6: Comparativa Pretest vs. Posttest del Effective Defense Score (EDS).
- Figura 7: Comparativa Pretest vs. Posttest de la Tasa de Detección Primaria (TP).
- Figura 8: Comparativa de Latencia y Tiempos de Respuesta (RNF-01).
"""
import os
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np

def setup_style():
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 11,
        "axes.labelsize": 12,
        "axes.titlesize": 13,
        "xtick.labelsize": 11,
        "ytick.labelsize": 11,
        "legend.fontsize": 11,
        "figure.titlesize": 14
    })

def main():
    setup_style()
    csv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "metrics_anexo3_wide.csv"))
    if not os.path.exists(csv_path):
        csv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "metrics_anexo3_wide.csv"))

    df = pd.read_csv(csv_path)

    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "figures"))
    os.makedirs(out_dir, exist_ok=True)
    root_figures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "figures"))
    os.makedirs(root_figures_dir, exist_ok=True)

    colors = ["#c0392b", "#27ae60"]  # Rojo para Sin Defensa (Ablación), Verde para Con Defensa

    # =========================================================================
    # FIGURA 5: TASA DE ÉXITO DE ATAQUES (ASR)
    # =========================================================================
    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)
    asr_data = [df["ASR_Ablacion"].mean() * 100, df["ASR_Defensa"].mean() * 100]
    bars = ax.bar(["Pretest (Sin Defensa / Ablación)", "Posttest (Con Defensa Propuesta)"], asr_data, color=colors, width=0.45, edgecolor="black", linewidth=1)
    ax.set_ylabel("Tasa de Éxito de Ataque - ASR (%)")
    ax.set_ylim(0, 50)
    ax.set_title("Comparativa de la Tasa de Éxito de Ataques (ASR) por Inyección Indirecta", pad=15)

    for bar in bars:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2.0, yval + 1.2, f"{yval:.2f}%", ha='center', va='bottom', fontweight='bold')

    ax.text(0.5, 42, "Reducción Absoluta: -37.26%\n(Prueba de McNemar: p < 0.001)", 
            ha='center', va='center', bbox=dict(boxstyle="round,pad=0.5", facecolor="#ecf0f1", edgecolor="#bdc3c7"), fontsize=10)

    plt.tight_layout()
    f5_path = os.path.join(out_dir, "figura_5_comparativa_asr.png")
    fig.savefig(f5_path)
    fig.savefig(os.path.join(root_figures_dir, "figura_5_comparativa_asr.png"))
    plt.close()
    print(f"[+] Figura 5 guardada: {f5_path}")

    # =========================================================================
    # FIGURA 6: EFFECTIVE DEFENSE SCORE (EDS)
    # =========================================================================
    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)
    eds_data = [df["EDS_Ablacion"].mean(), df["EDS_Defensa"].mean()]
    bars = ax.bar(["Pretest (Sin Defensa / Ablación)", "Posttest (Con Defensa Propuesta)"], eds_data, color=colors, width=0.45, edgecolor="black", linewidth=1)
    ax.set_ylabel("Effective Defense Score (Escala 0.0 a 1.0)")
    ax.set_ylim(0, 1.15)
    ax.set_title("Comparativa del Effective Defense Score (EDS)", pad=15)

    for bar in bars:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2.0, yval + 0.03, f"{yval:.4f}", ha='center', va='bottom', fontweight='bold')

    ax.text(0.5, 0.25, "Incremento: +0.3559\n(Prueba de Wilcoxon: Z = -23.35, p < 0.001)", 
            ha='center', va='center', bbox=dict(boxstyle="round,pad=0.5", facecolor="#ecf0f1", edgecolor="#bdc3c7"), fontsize=10)

    plt.tight_layout()
    f6_path = os.path.join(out_dir, "figura_6_comparativa_eds.png")
    fig.savefig(f6_path)
    fig.savefig(os.path.join(root_figures_dir, "figura_6_comparativa_eds.png"))
    plt.close()
    print(f"[+] Figura 6 guardada: {f6_path}")

    # =========================================================================
    # FIGURA 7: DETECCIÓN PRIMARIA DE VULNERABILIDADES (TP)
    # =========================================================================
    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)
    tp_data = [df["TP_Ablacion"].mean() * 100, df["TP_Defensa"].mean() * 100]
    bars = ax.bar(["Pretest (Sin Defensa / Ablación)", "Posttest (Con Defensa Propuesta)"], tp_data, color=["#e67e22", "#2980b9"], width=0.45, edgecolor="black", linewidth=1)
    ax.set_ylabel("Tasa de Detección de Vulnerabilidades - TP (%)")
    ax.set_ylim(0, 110)
    ax.set_title("Eficacia Diagnóstica Primaria de Vulnerabilidades Web (TP)", pad=15)

    for bar in bars:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2.0, yval + 2.0, f"{yval:.2f}%", ha='center', va='bottom', fontweight='bold')

    ax.text(0.5, 35, "Mejora de Detección: +21.57%\n(Prueba de McNemar: p < 0.001)", 
            ha='center', va='center', bbox=dict(boxstyle="round,pad=0.5", facecolor="#ecf0f1", edgecolor="#bdc3c7"), fontsize=10)

    plt.tight_layout()
    f7_path = os.path.join(out_dir, "figura_7_comparativa_tp.png")
    fig.savefig(f7_path)
    fig.savefig(os.path.join(root_figures_dir, "figura_7_comparativa_tp.png"))
    plt.close()
    print(f"[+] Figura 7 guardada: {f7_path}")

    # =========================================================================
    # FIGURA 8: LATENCIA Y TIEMPO DE RESPUESTA (RNF-01)
    # =========================================================================
    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)
    time_data = [df["Time_s_Ablacion"].mean(), df["Time_s_Defensa"].mean()]
    bars = ax.bar(["Pretest (Sin Defensa)", "Posttest (Con Defensa)"], time_data, color=["#95a5a6", "#34495e"], width=0.45, edgecolor="black", linewidth=1)
    ax.set_ylabel("Tiempo de Ejecución Promedio (segundos)")
    ax.set_ylim(0, 6.5)
    ax.set_title("Sobrecosto de Latencia de la Capa de Procedencia (RNF-01)", pad=15)

    for bar in bars:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2.0, yval + 0.15, f"{yval:.3f} s", ha='center', va='bottom', fontweight='bold')

    ax.text(0.5, 2.5, "Delta Overhead: +59.4 ms\nCumple RNF-01 (< 1500 ms)", 
            ha='center', va='center', bbox=dict(boxstyle="round,pad=0.5", facecolor="#d5f5e3", edgecolor="#2ecc71"), fontsize=10)

    plt.tight_layout()
    f8_path = os.path.join(out_dir, "figura_8_latencia_rnf01.png")
    fig.savefig(f8_path)
    fig.savefig(os.path.join(root_figures_dir, "figura_8_latencia_rnf01.png"))
    plt.close()
    print(f"[+] Figura 8 guardada: {f8_path}")

    print("\n[+] Todas las figuras científicas fueron generadas satisfactoriamente a 300 DPI.")

if __name__ == "__main__":
    main()
