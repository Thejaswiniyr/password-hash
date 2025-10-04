# Use RAGFlow's exact image as base (Python 3.10.12)
FROM infiniflow/ragflow:v0.20.5-slim

# Set working directory
WORKDIR /ragflow

# Copy our hash service script
COPY ragflow_hash_api.py /ragflow/ragflow_hash_api.py

# Copy RAGFlow modules
COPY api /ragflow/api
COPY rag /ragflow/rag

# Copy RSA key files needed for encryption/decryption
COPY conf/public.pem /ragflow/conf/public.pem
COPY conf/private.pem /ragflow/conf/private.pem

# Expose port
EXPOSE 8082

# Run our hash API service
CMD ["python", "ragflow_hash_api.py"]