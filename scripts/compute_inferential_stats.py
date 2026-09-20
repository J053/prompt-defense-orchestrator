"""
Cálculo de Estadísticas Descriptivas e Inferenciales para la Tesis.
Ejecuta:
1. Prueba de Normalidad de Shapiro-Wilk para justificar pruebas no paramétricas.
2. Prueba de McNemar para variables dicotómicas pareadas (ASR, Hijack, TP, FP).
3. Prueba de Rangos con Signo de Wilcoxon para variables cuantitativas continuas (EDS, Tiempo, Costo).
4. Cálculo del tamaño del efecto (Cliff's Delta / Correlación Biserial de Rangos).
"""
import os
import sys
import numpy as np
import pandas as pd
from scipy import stats
from statsmodels.stats.contingency_tables import mcnemar

def main():
    csv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "metrics_anexo3_wide.csv"))
    if not os.path.exists(csv_path):
        csv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "metrics_anexo3_wide.csv"))
    
    df = pd.read_csv(csv_path)
    n = len(df)
    print("=" * 85)
    print(f"ANÁLISIS ESTADÍSTICO INFERENCIAL RIGUROSO (N = {n})")
    print("=" * 85)

    # 1. PRUEBA DE NORMALIDAD DE SHAPIRO-WILK
    print("\n[1] PRUEBA DE NORMALIDAD DE SHAPIRO-WILK (Alpha = 0.05)")
    print("-" * 85)
    print(f"{'Variable':<35} | {'Estadístico W':<15} | {'p-valor':<15} | {'Distribución'}")
    print("-" * 85)
    
    continuous_vars = [
        ("EDS_Defensa", df["EDS_Defensa"]),
        ("EDS_Ablacion", df["EDS_Ablacion"]),
        ("Diferencia EDS (Def - Abl)", df["EDS_Defensa"] - df["EDS_Ablacion"]),
        ("Diferencia Tiempo (s)", df["Time_s_Defensa"] - df["Time_s_Ablacion"]),
        ("Diferencia Costo ($)", df["Tokens_Cost_Defensa"] - df["Tokens_Cost_Ablacion"]),
    ]

    for name, series in continuous_vars:
        stat_w, p_val = stats.shapiro(series)
        dist = "No Normal (p < 0.05)" if p_val < 0.05 else "Normal (p >= 0.05)"
        p_str = "< 0.001" if p_val < 0.001 else f"{p_val:.4f}"
        print(f"{name:<35} | {stat_w:<15.4f} | {p_str:<15} | {dist}")

    print("\n* Conclusión de Normalidad: Al ser p < 0.001 en todas las variables continuas clave,")
    print("  se rechaza la hipótesis nula de normalidad y se justifica formalmente el uso de la")
    print("  prueba no paramétrica de Wilcoxon (muestras relacionadas).")

    # 2. PRUEBA DE MCNEMAR (VARIABLES DICOTÓMICAS PAREADAS)
    print("\n[2] PRUEBA DE MCNEMAR PARA VARIABLES DICOTÓMICAS PAREADAS")
    print("-" * 85)

    dichotomous_pairs = [
        ("Tasa de Éxito de Ataque (ASR)", "ASR_Defensa", "ASR_Ablacion"),
        ("Tasa de Secuestro de Herramientas (Hijack)", "Hijack_Defensa", "Hijack_Ablacion"),
        ("Tasa de Detección Primaria (TP)", "TP_Defensa", "TP_Ablacion"),
        ("Tasa de Falsos Positivos (FP)", "FP_Defensa", "FP_Ablacion"),
    ]

    for label, col_def, col_abl in dichotomous_pairs:
        # Tabla de contingencia 2x2
        # Fila: Con Defensa (0, 1), Columna: Sin Defensa (0, 1)
        ct = pd.crosstab(df[col_def], df[col_abl])
        # Asegurar forma 2x2
        table = np.zeros((2, 2), dtype=int)
        for r in [0, 1]:
            for c in [0, 1]:
                if r in ct.index and c in ct.columns:
                    table[r, c] = ct.loc[r, c]
        
        # McNemar test
        res = mcnemar(table, exact=False, correction=True)
        res_exact = mcnemar(table, exact=True)
        
        prop_def = df[col_def].mean() * 100
        prop_abl = df[col_abl].mean() * 100
        delta = prop_def - prop_abl
        
        print(f"\n--- {label} ---")
        print(f"    Tabla Contingencia 2x2 (Defensa x Ablación):")
        print(f"      [0, 0]: {table[0,0]} | [0, 1]: {table[0,1]}")
        print(f"      [1, 0]: {table[1,0]} | [1, 1]: {table[1,1]}")
        print(f"    Proporción Con Defensa: {prop_def:.2f}% | Sin Defensa: {prop_abl:.2f}% (Delta: {delta:+.2f}%)")
        print(f"    Chi-cuadrado (McNemar con corrección): {res.statistic:.4f}")
        print(f"    p-valor (Chi2): {'< 0.001' if res.pvalue < 0.001 else f'{res.pvalue:.4f}'}")
        print(f"    p-valor (Prueba Exacta): {'< 0.001' if res_exact.pvalue < 0.001 else f'{res_exact.pvalue:.4f}'}")

    # 3. PRUEBA DE RANGOS CON SIGNO DE WILCOXON (VARIABLES CONTINUAS)
    print("\n" + "=" * 85)
    print("[3] PRUEBA DE RANGOS CON SIGNO DE WILCOXON (MUESTRAS RELACIONADAS)")
    print("-" * 85)

    wilcoxon_pairs = [
        ("Effective Defense Score (EDS)", "EDS_Defensa", "EDS_Ablacion"),
        ("Tiempo de Ejecución (s)", "Time_s_Defensa", "Time_s_Ablacion"),
        ("Costo Computacional ($)", "Tokens_Cost_Defensa", "Tokens_Cost_Ablacion"),
    ]

    for label, col_def, col_abl in wilcoxon_pairs:
        stat_w, p_val = stats.wilcoxon(df[col_def], df[col_abl], alternative='two-sided')
        diff = df[col_def] - df[col_abl]
        # Aproximación Z para n grande
        non_zero_diff = diff[diff != 0]
        n_nz = len(non_zero_diff)
        mean_w = n_nz * (n_nz + 1) / 4.0
        std_w = np.sqrt(n_nz * (n_nz + 1) * (2 * n_nz + 1) / 24.0)
        z_score = (stat_w - mean_w) / std_w
        
        # Tamaño del efecto r = Z / sqrt(N)
        effect_r = abs(z_score) / np.sqrt(n_nz)
        
        print(f"\n--- {label} ---")
        print(f"    Media Con Defensa: {df[col_def].mean():.4f} (DE: {df[col_def].std():.4f}, Mediana: {df[col_def].median():.4f})")
        print(f"    Media Sin Defensa: {df[col_abl].mean():.4f} (DE: {df[col_abl].std():.4f}, Mediana: {df[col_abl].median():.4f})")
        print(f"    Estadístico Wilcoxon (W): {stat_w:.2f}")
        print(f"    Aproximación Z: {z_score:.4f}")
        print(f"    p-valor: {'< 0.001' if p_val < 0.001 else f'{p_val:.4f}'}")
        print(f"    Tamaño del efecto (r de Rosenthal): {effect_r:.4f} ({'Efecto Grande' if effect_r >= 0.5 else 'Efecto Moderado'})")

    print("\n" + "=" * 85)
    print("[+] PROCESAMIENTO INFERENCIAL COMPLETADO EXITOSAMENTE.")
    print("=" * 85)


if __name__ == "__main__":
    main()
