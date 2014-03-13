sed -i '1i digraph g {' mem_graph.dot
echo "}" >> mem_graph.dot
#circo -Tpdf mem_graph.dot -o mem_graph.pdf
dot -Tpdf mem_graph.dot -o mem_graph.pdf
evince mem_graph.pdf
