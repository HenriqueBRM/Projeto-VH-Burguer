using VH_Burguer.Domains;

namespace VH_Burguer.Interfaces
{
    public interface IProdutoRepository
    {
        List<Produto> Listar();
        Produto ObterPorId(int id);
        byte[] ObterImagem(int id);
        bool NomeExiste(string nome, int? produtoIdAtual = null);
        void Adicionar(Produto produto, List<int> categoriaIds);
        void Atualizar(Produto produto, List<int> categoriaIds);
        void Remover(int id);
    }
}
