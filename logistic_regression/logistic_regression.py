import numpy as np
from pandas import DataFrame


class LogisticRegression:
    """
    Class that implements a Softmax Logistic Regression model

    Attributes:
    - weights: np.ndarray containing k weights for each of the k features
    - bias: np.ndarray containing k (float) bias terms for each of the k features
    """
    def __init__(self) -> None:
        self.weights: np.ndarray = None
        self.bias: np.ndarray = None

    def fit(
            self,
            X: np.ndarray,
            y: np.ndarray,
            learning_rate: float = 0.01,
            epochs: int = 1000,
            batch_size: int = 32,
            verbose: bool = False
        ) -> np.ndarray:
        """
        Fit the model to the data. The loss function used is the cross-entropy loss.

        A great explanation of cross-entropy loss can be found here:
        https://eli.thegreenplace.net/2016/the-softmax-function-and-its-derivative/

        Parameters:
        - X: np.ndarray of shape (m, n) containing the training data
        - y: np.ndarray of shape (m, k) containing the training labels
        - learning_rate: float learning rate for gradient descent
        - epochs: int number of epochs to train the model
        - batch_size: int number of samples to use in each mini-batch
        """
        X = X.to_numpy() if isinstance(X, DataFrame) else X
        y = y.to_numpy() if isinstance(y, DataFrame) else y
        losses = np.zeros(epochs)

        # Make sure the prediction shapes are correct
        if y.ndim == 1:
            y = y.reshape(-1, 1)

        self.weights = np.random.uniform(-0.01, 0.01, (X.shape[1], y.shape[1]))
        self.bias = np.random.uniform(-0.01, 0.01, y.shape[1])

        for epoch in range(epochs):
            y_pred = self._forward(X)
            loss = self._loss(y, y_pred)
            losses[epoch] = loss

            if verbose and epoch % 100 == 0:
                print(f"Loss at epoch {epoch}: {loss}")

            dW = np.zeros_like(self.weights)
            db = np.zeros_like(self.bias)

            # Compute the gradients using a mini-batch
            batch_indices = np.random.choice(X.shape[0], batch_size, replace=False)
            X_batch = X[batch_indices]
            y_batch = y[batch_indices]
            y_pred_batch = y_pred[batch_indices]

            # Could be optimized by vectorizing the computation
            # But this is easier to understand
            for Xk, yk, yk_pred in zip(X_batch, y_batch, y_pred_batch):
                # i is the numer of classes / independent predictions
                # J is the number of features
                for i in range(yk.shape[0]):
                    for j in range(Xk.shape[0]):
                        y_index = np.argmax(yk)
                        dt_yi = 1 if y_index == i else 0

                        dW[j][i] += (yk_pred[i] - dt_yi) * Xk[j]
                        db[i] += (yk_pred[i] - dt_yi)

            dW /= batch_size
            db /= batch_size

            # Update the weights and bias
            self.weights -= learning_rate * dW
            self.bias -= learning_rate * db

        return losses

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict the labels for the data.

        Parameters:
        - X: np.ndarray of shape (m, n) containing the data

        Returns:
        - np.ndarray of shape (m, k) containing the predicted labels
        """
        X = X.to_numpy() if isinstance(X, DataFrame) else X
        y_pred = self._forward(X)

        # Avoid using np.round because it can round all values to 0
        result = np.zeros_like(y_pred)
        result[np.arange(len(y_pred)), y_pred.argmax(1)] = 1

        return result
    
    def _softmax(self, S: np.ndarray) -> np.ndarray:
        """
        Compute the softmax of a vector in a numerically stable way.
        """
        shiftS = S - np.max(S, axis=1, keepdims=True)
        expS = np.exp(shiftS)
        return expS / np.sum(expS, axis=1, keepdims=True)

    def _forward(self, X: np.ndarray) -> np.ndarray:
        """
        Forward pass through the network.
        """
        logits = np.dot(X, self.weights) + self.bias
        # print(f"X: {X[:5]}")
        # print(f"Logits: {logits[:5]}")
        return self._softmax(logits)
    
    def _loss(self, y: np.ndarray, y_pred: np.ndarray) -> float:
        """
        Compute the cross-entropy loss. For two classes, this is
        equivalent to the binary cross-entropy loss.
        """
        return np.mean(-np.sum(y * np.log(y_pred + 1e-8), axis=1))
