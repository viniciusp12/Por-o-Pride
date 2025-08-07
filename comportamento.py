from sklearn import tree

# [0] - Não é um Ransomware
# [1] - Possível Ransomware
features = [[3, 2, 2, 1, 0], [2, 0, 15, 0, 0], [20, 3, 0, 0, 0], [0, 0, 2, 0, 0], [0, 0, 2, 0, 5], [0, 0, 0, 0, 0], [2, 2, 0, 0, 0], [0, 2, 0, 20, 0], [0, 2, 0, 2, 0],[3, 2, 2, 1, 8], [2, 0, 15, 0, 5], [11, 0, 0, 11, 0], [0, 10, 0, 2, 30], [2, 10, 3, 1, 0], [0, 40, 40, 0, 30]]
labels = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1]
classifying = tree.DecisionTreeClassifier()
classifying.fit(features, labels)


def avaliar(arquivos_criados, arquivos_mods, arquivos_movs, arquivos_delets, arquivos_edits):
    monitor = classifying.predict([[arquivos_criados, arquivos_mods, arquivos_movs, arquivos_delets, arquivos_edits]])
    if monitor == 0:
        pass
    elif monitor == 1:
        return True
