from typing import List, Tuple, Dict
from math import log2
from pandas import DataFrame
import numpy as np


def shannon_entropy(probabilities: List[float]) -> float:
    """
    Calculate the Shannon entropy of a list of probabilities.
    """
    return -sum(p * log2(p) for p in probabilities if p != 0)


def gini_impurity(probabilities: List[float]) -> float:
    """
    Calculate the Gini impurity of a list of probabilities.
    """
    return 1 - sum(p ** 2 for p in probabilities)


class DecisionTreeNode():
    """
    A node in the decision tree.
    """
    def __init__(self) -> None:
        self.entropy: float = None
        self.column: int = None
        self.split_value: float = None
        self.probs: Dict[float, float] = None
        self.prediction: float = None
        self.left: DecisionTreeNode = None
        self.right: DecisionTreeNode = None


class DecisionTree():
    """
    A decision tree classifier.
    
    Parameters:
    - max_depth: The maximum depth of the tree.
    - min_info_gain: The minimum information gain required to split a node.
    """
    def __init__(self, max_depth: int = 5, min_info_gain: float = 0.1) -> None:
        self.tree: DecisionTreeNode = None
        self.max_depth = max_depth
        self.min_info_gain = min_info_gain

    def fit(self, X: np.ndarray | DataFrame, y: np.ndarray) -> None:
        """
        Fit the decision tree to the data.
        """
        X = X.to_numpy() if isinstance(X, DataFrame) else X
        self.tree = self._build_tree(X, y, 0)

    def predict(self, X: np.ndarray | DataFrame) -> np.ndarray:
        X = X.to_numpy() if isinstance(X, DataFrame) else X

        if self.tree is None:
            raise ValueError("Tree not fitted")
        
        if len(X.shape) == 1:
            return self._predict_one(X)

        return np.array([self._predict_one(x) for x in X])

    def _entropy(self, data: np.ndarray) -> float:
        probabilities = [np.mean(data == c) for c in np.unique(data)]
        return shannon_entropy(probabilities)
    
    def _partition_entropy(self, subsets: List[np.ndarray]) -> float:
        total_count = sum(len(subset) for subset in subsets)
        return sum(len(subset) / total_count * self._entropy(subset) for subset in subsets)
    
    def _split(self, X: np.ndarray, y: np.ndarray, column: int, value: float) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        column_values = X[:, column]
        mask = column_values <= value
        left_X, right_X = X[mask], X[~mask]
        left_y, right_y = y[mask], y[~mask]

        return left_X, right_X, left_y, right_y
    
    def _best_column_split(self, X: np.ndarray, y: np.ndarray, column: int) -> Tuple[float, float]:
        min_entropy = float('inf')
        best_value = None

        # Simplified best split search
        unique_values = np.unique(X[:, column])
        sorted_values = np.sort(unique_values)

        max_splits = 20
        step = max(len(sorted_values) // max_splits, 1)

        for i in range(0, len(sorted_values), step):
            value = sorted_values[i]
            _, _, left_y, right_y = self._split(X, y, column, value)
            entropy = self._partition_entropy([left_y, right_y])

            if entropy < min_entropy:
                min_entropy = entropy
                best_value = value

        return best_value, min_entropy

    def _best_split(self, X: np.ndarray, y: np.ndarray) -> Tuple[int, float, float]:
        min_entropy = float('inf')
        best_column = None
        split_value = None

        for column in range(X.shape[1]):
            value, entropy = self._best_column_split(X, y, column)

            if entropy < min_entropy:
                min_entropy = entropy
                best_column = column
                split_value = value

        return best_column, split_value, min_entropy
    
    def _build_tree(self, X: np.ndarray, y: np.ndarray, depth: int) -> DecisionTreeNode:
        if depth == self.max_depth:
            return None
        
        # Find the best column to split on
        column, value, entropy = self._best_split(X, y)

        # Compute the information gain
        gain = self._entropy(y) - entropy
        
        # Split the data
        left_X, right_X, left_y, right_y = self._split(X, y, column, value)

        node = DecisionTreeNode()
        node.entropy = entropy
        node.column = column
        node.split_value = value
        node.probs = {c: np.mean(y == c) for c in np.unique(y)}
        node.prediction = max(node.probs, key=node.probs.get)

        # Stop if information gain is too low or if the node is pure
        if gain < self.min_info_gain or entropy == 0:
            return node
        
        node.left = self._build_tree(left_X, left_y, depth + 1)
        node.right = self._build_tree(right_X, right_y, depth + 1)

        return node


    def _predict_one(self, x: np.ndarray) -> float:
        node = self.tree
        prediction = None

        while node:
            prediction = node.prediction
            if x[node.column] <= node.split_value:
                node = node.left
            else:
                node = node.right

        return prediction
